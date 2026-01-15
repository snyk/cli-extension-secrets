package filefilter

import (
	"context"
	"runtime"
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/utils"
)

// streamAllowedFiles iterates over multiple input paths, applies rules from specific
// ignore files (.gitignore) combined with rules from customGlobPatterns, and returns a single merged channel containing
// only the file paths that are allowed (not ignored).
func streamAllowedFiles(
	ctx context.Context,
	inputPaths []string,
	ignoreFilenames []string,
	customGlobPatterns []string,
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

			maxThreadCount := runtime.NumCPU()
			// Initialize the file walker/filter
			filter := utils.NewFileFilter(rootPath, logger, utils.WithThreadNumber(maxThreadCount))

			// Get rules from the passed filenames
			foundIgnoreRules, err := filter.GetRules(ignoreFilenames)
			if err != nil {
				// Log and skip this path, but don't crash the whole stream
				logger.Error().Err(err).Str("path", rootPath).Msg("failed to parse ignore rules, skipping path")
				return
			}

			// Merge global custom rules with the specific rules found in files.
			localRules := make([]string, 0, len(customGlobPatterns)+len(foundIgnoreRules))
			localRules = append(localRules, customGlobPatterns...)
			localRules = append(localRules, foundIgnoreRules...)

			//  Get the stream of allowed files.
			allFiles := filter.GetAllFiles()
			pathFileStream := filter.GetFilteredFiles(allFiles, localRules)

			for file := range pathFileStream {
				select {
				case mergedFiles <- file:
				case <-ctx.Done():
					return
				}
			}
		}(path)
	}

	// Closer: Monitor the WaitGroup and close the channel when all paths are done.
	go func() {
		wg.Wait()
		close(mergedFiles)
	}()
	return mergedFiles
}
