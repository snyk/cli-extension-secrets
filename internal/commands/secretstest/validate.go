package secretstest

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"

	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

// Validation limits for user input.
const (
	MaxTargetNameLength      = 256
	MaxTargetReferenceLength = 256
	MaxFileOutputPathLength  = 4096
)

var (
	validOptionsCriticality = map[string]struct{}{
		"critical": {}, "high": {}, "medium": {}, "low": {},
	}
	validOptionsProjectEnv = map[string]struct{}{
		"frontend": {}, "backend": {}, "internal": {}, "external": {}, "mobile": {}, "saas": {}, "onprem": {}, "hosted": {}, "distributed": {},
	}
	validOptionsProjectLifecycle = map[string]struct{}{
		"production": {}, "development": {}, "sandbox": {},
	}
)

type flagWithOptions struct {
	name         string
	allowEmpty   bool
	singleChoice bool
	validOptions map[string]struct{}
}

func validateAndPrepareInput(
	config configuration.Configuration,
	errorFactory *ErrorFactory,
) (orgID, inputPath string, err error) {
	if !config.GetBool(FeatureFlagIsSecretsEnabled) {
		return "", "", errorFactory.NewFeatureNotEnabledError(FeatureNotEnabledMsg)
	}

	unsupportedErr := validateUnsupportedFlags(config)
	if unsupportedErr != nil {
		return "", "", unsupportedErr
	}

	orgID = config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return "", "", errorFactory.NewValidationFailureError(NoOrgProvidedMsg)
	}

	if e := validateFlagsConfig(config); e != nil {
		return "", "", errorFactory.NewValidationFailureError(e.Error())
	}

	inputPaths := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(inputPaths) != 1 {
		return "", "", errorFactory.NewValidationFailureError(SingleInputPathMsg)
	}

	absPath, e := filepath.Abs(inputPaths[0])
	if e != nil {
		absErr := fmt.Errorf("could not get absolute path '%s': %w", inputPaths[0], e)
		return "", "", errorFactory.NewGeneralSecretsFailureError(absErr, AbsPathFailureMsg)
	}

	return orgID, sanitizePath(absPath), nil
}

func validateUnsupportedFlags(config configuration.Configuration) error {
	if config.GetBool(FlagJSON) || config.IsSet(FlagJSONFileOutput) {
		return cli_errors.NewInvalidFlagOptionError(JSONNotSupportedMsg)
	}
	if config.GetBool(FlagSARIF) || config.IsSet(FlagSARIFFileOutput) {
		return cli_errors.NewInvalidFlagOptionError(SARIFNotSupportedMsg)
	}
	return nil
}

func validateFlagsConfig(config configuration.Configuration) error {
	// check --report related flags only if --report is true, otherwise flags are ignored
	err := validateReportConfig(config)
	if err != nil {
		return err
	}

	if config.IsSet(FlagSeverityThreshold) {
		flag := flagWithOptions{
			name:         FlagSeverityThreshold,
			allowEmpty:   false,
			singleChoice: true,
			validOptions: validOptionsCriticality,
		}
		err := validateFlagValue(config, flag)
		if err != nil {
			return err
		}
	}

	if err := validateRemoteRepoURL(config); err != nil {
		return err
	}

	return validateFileOutputPaths(config)
}

/*
This validates config flags that only work together with --report:
--project-environment, --project-business-criticality, --project-lifecycle
--project-tags.
*/
func validateReportConfig(config configuration.Configuration) error {
	if !config.GetBool(FlagReport) {
		return validateFlagsWithoutReportConfig(config)
	}

	flags := []flagWithOptions{
		{
			name:         FlagProjectEnvironment,
			allowEmpty:   false,
			validOptions: validOptionsProjectEnv,
		},
		{
			name:         FlagProjectLifecycle,
			allowEmpty:   false,
			validOptions: validOptionsProjectLifecycle,
		},
		{
			name:         FlagProjectBusinessCriticality,
			allowEmpty:   false,
			validOptions: validOptionsCriticality,
		},
	}

	for _, flag := range flags {
		if config.IsSet(flag.name) {
			err := validateFlagValue(config, flag)
			if err != nil {
				return err
			}
		}
	}

	if err := validateTags(config); err != nil {
		return err
	}

	return validateStringLengthLimits(config)
}

func validateFlagsWithoutReportConfig(config configuration.Configuration) error {
	reportFlags := []string{
		FlagTargetReference,
		FlagTargetName,
		FlagProjectEnvironment,
		FlagProjectLifecycle,
		FlagProjectBusinessCriticality,
		FlagProjectTags,
	}

	for _, flagName := range reportFlags {
		if config.IsSet(flagName) {
			errMsg := fmt.Sprintf("Invalid use of --%s, it can only be used in combination with the --report option", flagName)
			return errors.New(errMsg)
		}
	}
	return nil
}

/*
Validates a config flag that can only take one of a specific set of values
e.g. --severity-threshold must be one of low, medium, high, critical.
*/
func validateFlagValue(config configuration.Configuration, flag flagWithOptions) error {
	rawFlagValue := config.GetString(flag.name)
	if rawFlagValue == "" && flag.allowEmpty {
		return nil
	}

	rawValues := strings.Split(rawFlagValue, ",")

	if len(rawValues) > 1 && flag.singleChoice {
		errMsg := fmt.Sprintf("Invalid --%s, please use one of %s. ", flag.name, strings.Join(getKeys(flag.validOptions), " | "))
		return errors.New(errMsg)
	}

	var invalidValues []string
	for _, v := range rawValues {
		if _, exists := flag.validOptions[v]; !exists {
			invalidValues = append(invalidValues, v)
		}
	}

	if len(invalidValues) > 0 {
		errMsg := fmt.Sprintf("Invalid --%s: %v. Possible values are: %v.",
			flag.name, strings.Join(invalidValues, ", "),
			strings.Join(getKeys(flag.validOptions), ", "),
		)
		if flag.allowEmpty {
			errMsg += fmt.Sprintf("\nTo clear all existing values, pass no values i.e. %s=", flag.name)
		}
		return errors.New(errMsg)
	}

	return nil
}

/*
	This validates the --project-tags config flag

format: KEY=VALUE
*/
func validateTags(config configuration.Configuration) error {
	// no flag is set no need to validate
	if !config.IsSet(FlagProjectTags) {
		return nil
	}

	rawTags := config.GetString(FlagProjectTags)
	if rawTags == "" {
		return nil
	}

	// tags must have a specific KEY=VALUE format
	tags := strings.Split(rawTags, ",")
	for _, t := range tags {
		tagParts := strings.Split(t, "=")
		if len(tagParts) != 2 {
			errMsg := fmt.Sprintf("The tag %s does not have an \"=\" separating the key and value. For example: %s=KEY=VALUE", t, FlagProjectTags)
			errMsg += fmt.Sprintf("\nTo clear all existing values, pass no values i.e. %s=", FlagProjectTags)
			return errors.New(errMsg)
		}
	}

	return nil
}

func parseExcludeFlag(config configuration.Configuration) ([]string, error) {
	if !config.IsSet(FlagExcludeFilePath) {
		return nil, nil
	}

	rawExcludeFlag := strings.TrimSpace(config.GetString(FlagExcludeFilePath))
	if rawExcludeFlag == "" {
		return nil, cli_errors.NewValidationFailureError("Empty --exclude argument. Did you mean --exclude=subdirectory?")
	}

	excludeGlobs, err := ff.ExpandExcludeNames(strings.Split(rawExcludeFlag, ","))
	if err != nil {
		return nil, cli_errors.NewValidationFailureError(
			"The --exclude argument must be a comma separated list of directory or file names and cannot contain a path.",
		)
	}
	return excludeGlobs, nil
}

func getKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}

func validateRemoteRepoURL(config configuration.Configuration) error {
	if !config.IsSet(FlagRemoteRepoURL) {
		return nil
	}

	rawURL := strings.TrimSpace(config.GetString(FlagRemoteRepoURL))
	if rawURL == "" {
		return nil
	}

	if isValidGitURL(rawURL) {
		return nil
	}

	errMsg := fmt.Sprintf("Invalid --%s: must be a valid git URL (e.g., https://github.com/org/repo.git or git@github.com:org/repo.git)", FlagRemoteRepoURL)
	return errors.New(errMsg)
}

var scpURLRegexp = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]*@[a-zA-Z0-9.-]+:[^/].*$`)

func isValidGitURL(rawURL string) bool {
	if scpURLRegexp.MatchString(rawURL) {
		return true
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	if parsedURL.Scheme == "" {
		return false
	}

	scheme := strings.ToLower(parsedURL.Scheme)

	if scheme == "file" {
		return parsedURL.Path != ""
	}

	if parsedURL.Host == "" {
		return false
	}

	allowedSchemes := map[string]struct{}{
		"http":    {},
		"https":   {},
		"git":     {},
		"ssh":     {},
		"git+ssh": {},
		"ssh+git": {},
	}
	_, ok := allowedSchemes[scheme]
	return ok
}

func validateStringLengthLimits(config configuration.Configuration) error {
	if config.IsSet(FlagTargetName) {
		value := config.GetString(FlagTargetName)
		if utf8.RuneCountInString(value) > MaxTargetNameLength {
			errMsg := fmt.Sprintf("Invalid --%s: exceeds maximum length of %d characters", FlagTargetName, MaxTargetNameLength)
			return errors.New(errMsg)
		}
	}

	if config.IsSet(FlagTargetReference) {
		value := config.GetString(FlagTargetReference)
		if utf8.RuneCountInString(value) > MaxTargetReferenceLength {
			errMsg := fmt.Sprintf("Invalid --%s: exceeds maximum length of %d characters", FlagTargetReference, MaxTargetReferenceLength)
			return errors.New(errMsg)
		}
	}

	return nil
}

func validateFileOutputPaths(config configuration.Configuration) error {
	outputFlags := []string{FlagJSONFileOutput, FlagSARIFFileOutput}

	for _, flagName := range outputFlags {
		if !config.IsSet(flagName) {
			continue
		}

		rawPath := config.GetString(flagName)
		if rawPath == "" {
			continue
		}

		if utf8.RuneCountInString(rawPath) > MaxFileOutputPathLength {
			errMsg := fmt.Sprintf("Invalid --%s: path exceeds maximum length of %d characters", flagName, MaxFileOutputPathLength)
			return errors.New(errMsg)
		}

		if strings.ContainsAny(rawPath, "\x00") {
			errMsg := fmt.Sprintf("Invalid --%s: path contains invalid characters", flagName)
			return errors.New(errMsg)
		}

		if err := validateOutputPathSafety(rawPath, flagName); err != nil {
			return err
		}
	}

	return nil
}

func validateOutputPathSafety(rawPath, flagName string) error {
	absPath, err := filepath.Abs(rawPath)
	if err != nil {
		errMsg := fmt.Sprintf("Invalid --%s: cannot resolve path", flagName)
		return errors.New(errMsg)
	}

	parentDir := filepath.Dir(absPath)
	info, statErr := os.Stat(parentDir)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil
		}
		errMsg := fmt.Sprintf("Invalid --%s: cannot access parent directory", flagName)
		return errors.New(errMsg)
	}

	if !info.IsDir() {
		errMsg := fmt.Sprintf("Invalid --%s: parent path is not a directory", flagName)
		return errors.New(errMsg)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		realParent, err := filepath.EvalSymlinks(parentDir)
		if err != nil {
			errMsg := fmt.Sprintf("Invalid --%s: cannot resolve symlinks in path", flagName)
			return errors.New(errMsg)
		}
		if strings.Contains(realParent, "..") {
			errMsg := fmt.Sprintf("Invalid --%s: symlink resolves to path with traversal", flagName)
			return errors.New(errMsg)
		}
	}

	return nil
}
