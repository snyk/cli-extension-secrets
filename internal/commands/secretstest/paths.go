//nolint:gocyclo // Pipeline complexity is high due to error handling and concurrency safety
package secretstest

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/snyk/cli-extension-secrets/pkg/filefilter"
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

type LocalFile struct {
	Path string
	Info os.FileInfo
}

// fileProcessingTask represents a path discovered by the walker that needs
// to be processed (stats fetched) and added to the results.
type fileProcessingTask struct {
	path string
	// cached entry from WalkDir to save a syscall.
	entry fs.DirEntry
}

func FindAllFiles(paths []string) ([]LocalFile, error) {
	pool, ctx := errgroup.WithContext(context.Background())

	// Set concurrency limit to 2x the number of CPU cores
	numWorkers := runtime.NumCPU() * 2

	// Buffered channel to decouple walking from processing.
	// Buffer size matches worker count to keep the pipeline flowing.
	tasksChan := make(chan fileProcessingTask, numWorkers)

	// Protect the slice with a Mutex since multiple workers will write to it
	var mu sync.Mutex
	allFiles := make([]LocalFile, 0)

	// Producer file walker
	pool.Go(func() error {
		defer close(tasksChan)

		for _, path := range paths {
			info, err := os.Stat(path)
			if err != nil {
				// Skip paths that don't exist
				if os.IsNotExist(err) {
					continue
				}
				return fmt.Errorf("failed to stat input path %q: %w", path, err)
			}

			if !info.IsDir() {
				// It's a file, send directly to workers
				select {
				case tasksChan <- fileProcessingTask{path: path, entry: nil}:
				case <-ctx.Done():
					// Prevent deadlock if consumers fail
					return ctx.Err()
				}
				continue
			}

			// Walk this directory and collect files.
			walkErr := filepath.WalkDir(path, func(walkPath string, d fs.DirEntry, err error) error {
				if err != nil {
					return fmt.Errorf("error accessing path %q during walk: %w", walkPath, err)
				}

				// We only want files, so if it's a directory, we skip adding it.
				if d.IsDir() {
					return nil
				}

				// Push task to workers.
				select {
				case tasksChan <- fileProcessingTask{path: walkPath, entry: d}:
				case <-ctx.Done():
					// Prevent deadlock if consumers fail.
					return ctx.Err()
				}
				return nil
			})

			if walkErr != nil {
				return fmt.Errorf("failed to walk directory %q: %w", path, walkErr)
			}
		}
		return nil
	})

	// Consumer worker pool
	for range numWorkers {
		pool.Go(func() error {
			for task := range tasksChan {
				// Check context in case another goroutine failed.
				if ctx.Err() != nil {
					return ctx.Err()
				}

				var info fs.FileInfo
				var err error

				// Optimization: If we have the DirEntry, use it.
				// Otherwise (for root files), fallback to os.Stat.
				if task.entry != nil {
					info, err = task.entry.Info()
				} else {
					info, err = os.Stat(task.path)
				}

				if err != nil {
					return fmt.Errorf("failed to get file info for %q: %w", task.path, err)
				}

				mu.Lock()
				allFiles = append(allFiles, LocalFile{
					Path: task.path,
					Info: info,
				})
				mu.Unlock()
			}
			return nil
		})
	}

	// Wait for all routines to finish
	if err := pool.Wait(); err != nil {
		return nil, fmt.Errorf("error listing files: %w", err)
	}

	return allFiles, nil
}

func ToFileFilterList(files []LocalFile) []filefilter.File {
	ffList := make([]filefilter.File, len(files))
	for i, file := range files {
		// Manually copy the fields to create the new type
		ffList[i] = filefilter.NewLocalFile(file.Path, file.Info)
	}
	return ffList
}
