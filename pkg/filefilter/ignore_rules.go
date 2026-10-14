package filefilter

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"gopkg.in/yaml.v3"
)

const (
	// gitIgnoreGlobPrefix marks rules that come from a .gitignore, so GAF can tell them apart when
	// tracked-file-aware filtering is enabled. It mirrors GAF's unexported constant.
	gitIgnoreGlobPrefix = "#gitignore:"
	// defaultGitRule is the rule GAF always prepends.
	defaultGitRule = "**/.git/**"
	gitDirName     = ".git"
	logKeyPath     = "path"
)

const (
	negation = "!"
	slash    = "/"
	all      = "**"
)

// dotSnykSections are the .snyk exclude sections honored by this extension. The framework defaults to "global" and "code".
var dotSnykSections = []utils.DotSnykExcludeSectionName{utils.DotSnykExcludeGlobal, utils.DotSnykExcludeSecrets}

// ruleRegexMetaChars are regex metacharacters that gitignore treats as literal, so they have to be escaped
// before the rule reaches the regex-based go-gitignore matcher. Glob syntax the matcher relies on is
// deliberately excluded.
var ruleRegexMetaChars = map[byte]bool{'$': true, '(': true, ')': true, '+': true, '|': true, '{': true, '}': true}

// ruleParser turns ignore files into the glob patterns understood by the GAF file filter.
type ruleParser struct {
	logger              *zerolog.Logger
	metacharacterFix    bool
	respectTrackedFiles bool
}

type dotSnykExclude struct {
	Path       string
	expireTime time.Time
	parseError error
}

func newRuleParser(invocationCtx workflow.InvocationContext, logger *zerolog.Logger) ruleParser {
	parser := ruleParser{logger: logger}
	if invocationCtx == nil {
		return parser
	}

	config := invocationCtx.GetConfiguration()
	if config == nil {
		return parser
	}

	parser.metacharacterFix = config.GetBool(utils.FF_FILE_FILTER_METACHARACTER_FIX)
	parser.respectTrackedFiles = config.GetBool(utils.FF_GITIGNORE_RESPECT_TRACKED_FILES)
	return parser
}

// ancestorIgnoreFiles returns the ignore files that apply to the files in dir, ordered from the outermost
// directory to dir so that rules closer to the file take precedence. Discovery stops at the directory
// containing .git, which is also returned as the project root. Without a git repository, every ancestor
// is considered and dir is returned as the root.
func ancestorIgnoreFiles(dir string, ignoreFilenames []string) (root string, ignoreFilePaths []string) {
	var dirs []string
	boundary := ""

	for current := dir; ; {
		dirs = append(dirs, current)

		if _, err := os.Lstat(filepath.Join(current, gitDirName)); err == nil {
			boundary = current
			break
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	root = dir
	if boundary != "" {
		root = boundary
	}

	for _, d := range slices.Backward(dirs) {
		for _, name := range ignoreFilenames {
			candidate := filepath.Join(d, name)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				ignoreFilePaths = append(ignoreFilePaths, candidate)
			}
		}
	}

	return root, ignoreFilePaths
}

// parseFiles builds the glob patterns for the given ignore files, preserving their order.
func (p ruleParser) parseFiles(ignoreFilePaths []string) ([]string, error) {
	var globs []string

	for _, ignoreFile := range ignoreFilePaths {
		content, err := os.ReadFile(ignoreFile) //nolint:gosec // ignore files are discovered next to the scanned file, not user-supplied input
		if err != nil {
			return nil, fmt.Errorf("failed to read ignore file %q: %w", ignoreFile, err)
		}

		switch filepath.Base(ignoreFile) {
		case dotSnykFile:
			globs = append(globs, p.parseDotSnykFile(content, filepath.Dir(ignoreFile))...)
		default:
			parsed := parseIgnoreFile(content, filepath.Dir(ignoreFile), p.metacharacterFix)
			if filepath.Base(ignoreFile) == gitIgnoreFile && p.respectTrackedFiles {
				for i, rule := range parsed {
					parsed[i] = gitIgnoreGlobPrefix + rule
				}
			}
			globs = append(globs, parsed...)
		}
	}

	return globs, nil
}

// parseDotSnykFile builds a list of glob patterns from a .snyk file.
func (p ruleParser) parseDotSnykFile(content []byte, dir string) []string {
	var rules utils.DotSnykRule
	if err := yaml.Unmarshal(content, &rules); err != nil {
		p.logger.Error().Err(err).Msg("parse .snyk failed")
		return nil
	}

	// Decode each requested section independently so a malformed section cannot drop the others.
	var excludes []dotSnykExclude
	for _, section := range dotSnykSections {
		node, ok := rules.Exclude[section]
		if !ok {
			continue
		}

		var sectionRules []dotSnykExclude
		if err := node.Decode(&sectionRules); err != nil {
			p.logger.Error().Err(err).Str("section", section.String()).Msg("parse .snyk section failed")
			continue
		}
		excludes = append(excludes, sectionRules...)
	}

	var globs []string
	for _, rule := range excludes {
		expired, err := rule.isExpired()
		if err != nil {
			// An invalid expiry is treated as not expired.
			p.logger.Error().Err(err).Msg("parse .snyk expires")
		}
		if expired {
			continue
		}

		// Absolute paths only make sense on the local file system, so they are skipped.
		if filepath.IsAbs(rule.Path) {
			p.logger.Warn().Str(logKeyPath, rule.Path).Msg("absolute paths are not supported when excluding files")
			continue
		}

		globs = append(globs, parseIgnoreRuleToGlobs(rule.Path, dir, nil, p.metacharacterFix)...)
	}

	return globs
}

func newDotSnykExclude(excludePath, expiresStr string) dotSnykExclude {
	expireTime, parseError := parseExpireTime(expiresStr)
	return dotSnykExclude{Path: excludePath, expireTime: expireTime, parseError: parseError}
}

func (dse *dotSnykExclude) isExpired() (expired bool, err error) {
	if dse.parseError != nil {
		return false, dse.parseError
	}
	if dse.expireTime.IsZero() {
		return false, nil
	}
	return time.Now().After(dse.expireTime), nil
}

// UnmarshalYAML decodes a .snyk exclude entry, either "- path" or "- path: {expires: ..., reason: ...}".
func (dse *dotSnykExclude) UnmarshalYAML(node *yaml.Node) error {
	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.ScalarNode:
		*dse = newDotSnykExclude(node.Value, "")
		return nil
	case yaml.MappingNode:
		if len(node.Content) < 2 {
			return fmt.Errorf("invalid mapping node: expected at least 2 content nodes, got %d", len(node.Content))
		}

		keyNode := node.Content[0]
		if keyNode.Kind != yaml.ScalarNode {
			return fmt.Errorf("expected scalar node for path, got %v", keyNode.Kind)
		}

		var expiresStr string
		if valueNode := node.Content[1]; valueNode.Kind == yaml.MappingNode {
			var metadata map[string]string
			if err := valueNode.Decode(&metadata); err != nil {
				return fmt.Errorf("failed to decode exclude metadata: %w", err)
			}
			expiresStr = metadata["expires"]
		}

		*dse = newDotSnykExclude(keyNode.Value, expiresStr)
		return nil
	default:
		return fmt.Errorf("unexpected yaml node kind: %v", node.Kind)
	}
}

func parseExpireTime(expiresStr string) (time.Time, error) {
	if expiresStr == "" {
		return time.Time{}, nil
	}

	formats := []string{time.RFC3339, time.RFC1123Z, time.DateOnly, time.StampMilli}

	var lastErr error
	for _, format := range formats {
		t, err := time.Parse(format, expiresStr)
		if err == nil {
			return t, nil
		}
		lastErr = err
	}

	return time.Time{}, fmt.Errorf("failed to parse expires time '%s': %w", expiresStr, lastErr)
}

// parseIgnoreFile builds a list of glob patterns from the content of a .gitignore style file located in dir.
func parseIgnoreFile(content []byte, dir string, metacharacterFix bool) []string {
	var ignores []string

	// Patterns that are not valid in a .gitignore.
	invalidRules := []string{"."}

	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		ignores = append(ignores, parseIgnoreRuleToGlobs(line, dir, invalidRules, metacharacterFix)...)
	}

	return ignores
}

func escapeIgnoreRuleMetaChars(rule string) string {
	var result strings.Builder
	for i := 0; i < len(rule); i++ {
		if ruleRegexMetaChars[rule[i]] {
			result.WriteByte('\\')
		}
		result.WriteByte(rule[i])
	}
	return result.String()
}

// escapeSpecialGlobCharsLegacy is the legacy escaping, which only handles "$".
func escapeSpecialGlobCharsLegacy(rule string) string {
	return strings.ReplaceAll(rule, "$", `\$`)
}

// joinGlob joins path parts like path.Join but preserves a leading "//" (UNC path prefix).
func joinGlob(parts ...string) string {
	result := path.Join(parts...)
	if len(parts) > 0 && strings.HasPrefix(parts[0], "//") && !strings.HasPrefix(result, "//") {
		result = "/" + result
	}
	return result
}

// parseIgnoreRuleToGlobs builds glob patterns from a single ignore rule, following the gitignore pattern format:
//
//	`/foo/` => `/foo/**`          `/foo` => `/foo/**`, `/foo`
//	`foo/`  => `**/foo/**`        `foo`  => `**/foo/**`, `**/foo`
//
// The patterns are anchored to the directory of the ignore file.
func parseIgnoreRuleToGlobs(rule, dir string, invalidRules []string, metacharacterFix bool) []string {
	if slices.Contains(invalidRules, strings.TrimSpace(rule)) {
		return nil
	}

	baseDir := filepath.ToSlash(dir)
	escape := escapeSpecialGlobCharsLegacy
	join := func(parts ...string) string { return filepath.ToSlash(filepath.Join(parts...)) }

	if metacharacterFix {
		baseDir = regexp.QuoteMeta(baseDir)
		// Undo escaping for chars that go-gitignore already escapes internally, otherwise they get double-escaped.
		baseDir = strings.ReplaceAll(baseDir, `\.`, ".")
		baseDir = strings.ReplaceAll(baseDir, `\?`, "?")
		escape = escapeIgnoreRuleMetaChars
		join = joinGlob
	}

	prefix := ""
	if strings.HasPrefix(rule, negation) {
		rule = rule[1:]
		prefix = negation
	}

	// A lone "/" has no effect in gitignore.
	if rule == slash {
		return nil
	}

	anchored := strings.HasPrefix(rule, slash) || strings.HasPrefix(rule, all)
	endingSlash := strings.HasSuffix(rule, slash)
	endingGlobstar := strings.HasSuffix(rule, all)

	// build applies the metacharacter handling of the selected mode to one candidate glob.
	build := func(parts ...string) string {
		if metacharacterFix {
			return prefix + join(parts...)
		}
		return escape(prefix + join(parts...))
	}
	ruleText := rule
	if metacharacterFix {
		ruleText = escape(rule)
	}

	var globs []string
	if anchored {
		if !endingGlobstar {
			globs = append(globs, build(baseDir, ruleText, all))
		}
		if !endingSlash {
			globs = append(globs, build(baseDir, ruleText))
		}
		return globs
	}

	if !endingGlobstar {
		globs = append(globs, build(baseDir, all, ruleText, all))
	}
	if !endingSlash {
		globs = append(globs, build(baseDir, all, ruleText))
	}
	return globs
}
