package filefilter

import (
	"context"
	"runtime"
	"sync"

	"golang.org/x/sync/errgroup"
)

type FileFilter interface {
	FilterOut(File) bool
}

// Filter runs the provided files through the filters concurrently.
func Filter(files []File, filters ...FileFilter) []File {
	if len(files) == 0 {
		return []File{}
	}
	// We use WithContext even though we don't expect errors,
	// so we can respect context cancellation if we wanted to expand this later.
	g, ctx := errgroup.WithContext(context.Background())
	numWorkers := runtime.NumCPU() * 2

	// Buffered channel for the files to check
	jobsChan := make(chan File, len(files))

	// Pre-fill the channel with the data we already have
	for _, f := range files {
		jobsChan <- f
	}
	close(jobsChan)

	var mu sync.Mutex
	results := make([]File, 0, len(files))

	// Start Workers
	for range numWorkers {
		g.Go(func() error {
			for file := range jobsChan {
				// Check for cancellation
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				shouldFilterOut := false
				for _, filter := range filters {
					if filter.FilterOut(file) {
						shouldFilterOut = true
						break
					}
				}

				if !shouldFilterOut {
					mu.Lock()
					results = append(results, file)
					mu.Unlock()
				}
			}
			return nil
		})
	}
	// We ignore the error here because our workers return nil or ctx error,
	// and we handle the empty result case naturally.
	if err := g.Wait(); err != nil {
		return results
	}
	return results
}
