package filefilter

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// streamAllowedFiles iterates over multiple input paths, applies rules from specific
// ignore files (.gitignore) combined with rules from customGlobPatterns, and returns a single merged channel containing
// only the file paths that are allowed (not ignored).
func streamAllowedFiles(
	ctx context.Context,
	inputPaths []string,
	ignoreFilenames []string,
	customGlobPatterns []string,
	invocationCtx workflow.InvocationContext,
	logger *zerolog.Logger,
) chan string {
	// Create the merged output channel
	mergedFiles := make(chan string, 100)
	var wg sync.WaitGroup

	for _, path := range inputPaths {
		wg.Add(1)

		go func(rootPath string) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}

			if absFile, ok := singleFileInput(rootPath, logger); ok {
				allowed, err := isSingleFileAllowed(absFile, ignoreFilenames, customGlobPatterns, invocationCtx, logger)
				if err != nil {
					// Log and skip this path, but don't crash the whole stream
					logger.Error().Err(err).Str(logKeyPath, rootPath).Msg("failed to parse ignore rules, skipping path")
					return
				}
				if allowed {
					select {
					case mergedFiles <- rootPath:
					case <-ctx.Done():
					}
				}
				return
			}

			streamDirectory(ctx, rootPath, ignoreFilenames, customGlobPatterns, invocationCtx, logger, mergedFiles)
		}(path)
	}

	// Closer: Monitor the WaitGroup and close the channel when all paths are done.
	go func() {
		wg.Wait()
		close(mergedFiles)
	}()
	return mergedFiles
}

// streamDirectory walks rootPath, applies the ignore rules found beneath it and sends the allowed files to out.
func streamDirectory(
	ctx context.Context,
	rootPath string,
	ignoreFilenames []string,
	customGlobPatterns []string,
	invocationCtx workflow.InvocationContext,
	logger *zerolog.Logger,
	out chan<- string,
) {
	// Initialize the file walker/filter, honoring the "global" and "secrets"
	// sections of any .snyk file (the framework defaults to "global" and "code").
	filter := newFileFilter(invocationCtx, rootPath, logger, filterOptions()...)

	// Get rules from the passed filenames
	foundIgnoreRules, err := filter.GetRules(ignoreFilenames)
	if err != nil {
		// Log and skip this path, but don't crash the whole stream
		logger.Error().Err(err).Str(logKeyPath, rootPath).Msg("failed to parse ignore rules, skipping path")
		return
	}

	// Merge global custom rules with the specific rules found in files.
	localRules := make([]string, 0, len(customGlobPatterns)+len(foundIgnoreRules))
	localRules = append(localRules, customGlobPatterns...)
	localRules = append(localRules, foundIgnoreRules...)

	//  Get the stream of allowed files.
	pathFileStream := filter.GetFilteredFiles(filter.GetAllFiles(), localRules)

	for file := range pathFileStream {
		select {
		case out <- file:
		case <-ctx.Done():
			return
		}
	}
}

func filterOptions() []utils.FileFilterOption {
	return []utils.FileFilterOption{
		utils.WithThreadNumber(runtime.NumCPU()),
		utils.WithDotSnykSections(dotSnykSections),
	}
}

// singleFileInput reports whether inputPath is an existing file and returns its absolute path.
func singleFileInput(inputPath string, logger *zerolog.Logger) (absFile string, ok bool) {
	info, err := os.Stat(inputPath)
	if err != nil {
		logger.Debug().Err(err).Str(logKeyPath, inputPath).Msg("could not stat input path, treating it as a directory")
		return "", false
	}
	if info.IsDir() {
		return "", false
	}

	abs, err := filepath.Abs(inputPath)
	if err != nil {
		logger.Debug().Err(err).Str(logKeyPath, inputPath).Msg("could not resolve absolute path, treating it as a directory")
		return "", false
	}

	return abs, true
}

// isSingleFileAllowed applies the ignore rules of every ancestor directory to a single file, without
// walking any directory tree. The file is matched by its absolute path, as the rules are anchored to
// the directory of their ignore file.
func isSingleFileAllowed(
	absFile string,
	ignoreFilenames []string,
	customGlobPatterns []string,
	invocationCtx workflow.InvocationContext,
	logger *zerolog.Logger,
) (bool, error) {
	root, ignoreFilePaths := ancestorIgnoreFiles(filepath.Dir(absFile), ignoreFilenames)

	foundRules, err := newRuleParser(invocationCtx, logger).parseFiles(ignoreFilePaths)
	if err != nil {
		return false, err
	}

	rules := make([]string, 0, len(customGlobPatterns)+len(foundRules)+1)
	rules = append(rules, customGlobPatterns...)
	rules = append(rules, defaultGitRule)
	rules = append(rules, foundRules...)

	filter := newFileFilter(invocationCtx, root, logger, filterOptions()...)

	in := make(chan string, 1)
	in <- absFile
	close(in)

	// Drain the stream so the filter's goroutines can finish.
	allowed := false
	for range filter.GetFilteredFiles(in, rules) {
		allowed = true
	}

	return allowed, nil
}

// newFileFilter builds the file filter from the invocation context when one is supplied, so
// filtering follows the invocation's configuration, and from defaults otherwise.
func newFileFilter(invocationCtx workflow.InvocationContext, rootPath string, logger *zerolog.Logger, options ...utils.FileFilterOption) *utils.FileFilter {
	if invocationCtx == nil {
		logger.Debug().Msg("invocation context not supplied; using default file filter configuration")
		return utils.NewFileFilter(
			rootPath,
			logger,
			options...,
		)
	}

	return invocationCtx.GetFileFilter(
		rootPath,
		options...,
	)
}
