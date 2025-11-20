package secretstest

import (
	"context"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/utils"

	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

func DetermineInputPaths(args []string, cwd string) []string {
	paths := []string{}
	for _, arg := range args {
		isCommand := slices.Contains([]string{"secrets", "test"}, arg)
		isFlag := strings.HasPrefix(arg, "-")
		if !isCommand && !isFlag {
			paths = append(paths, arg)
		}
	}
	if len(paths) == 0 {
		paths = append(paths, cwd)
	}
	return paths
}

// FilterInputPaths iterates over multiple input paths, applies specific ignore rules
// found in each path, and returns a single merged
// channel containing all relevant, filtered file paths.
func FilterInputPaths(ctx context.Context, inputPaths []string, logger *zerolog.Logger) chan string {
	// Create the merged output channel
	mergedFiles := make(chan string, 100)
	var wg sync.WaitGroup

	for _, path := range inputPaths {
		wg.Add(1)

		go func(p string) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}

			maxThreadCount := runtime.NumCPU()
			filter := utils.NewFileFilter(p, logger, utils.WithThreadNumber(maxThreadCount))
			foundIgnoreRules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
			if err != nil {
				// Stop this specific path, but don't crash
				logger.Error().Err(err).Str("path", p).Msg("failed to get ignore files, skipping path")
				return
			}

			localRules := ff.GetCustomGlobFileFilters()
			localRules = slices.Grow(localRules, len(foundIgnoreRules))
			localRules = append(localRules, foundIgnoreRules...)

			// Get the file stream
			pathFileStream := filter.GetFilteredFiles(filter.GetAllFiles(), localRules)

			// Fan-In: Pipe files to main channel
			for file := range pathFileStream {
				select {
				case mergedFiles <- file:
				case <-ctx.Done():
					return
				}
			}
		}(path)
	}

	go func() {
		wg.Wait()
		close(mergedFiles)
	}()

	return mergedFiles
}
