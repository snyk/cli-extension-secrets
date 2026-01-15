package filefilter

import (
	"context"
	"runtime"
	"sync"

	"github.com/rs/zerolog"
)

var ignoreFiles = []string{".gitignore"}

// FileFilter defines the contract for any logic that decides if a file should be dropped.
type FileFilter interface {
	FilterOut(path string) bool
}

// Pipeline holds the configuration for the filtering process.
type Pipeline struct {
	logger      *zerolog.Logger
	concurrency int
	filters     []FileFilter
}

// Option defines the functional option type.
type Option func(*Pipeline)

// NewPipeline creates a filter pipeline with reasonable defaults.
// Default concurrency is set to runtime.NumCPU().
func NewPipeline(opts ...Option) *Pipeline {
	// Default values
	p := &Pipeline{
		concurrency: runtime.NumCPU(),
		filters:     []FileFilter{},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithConcurrency allows overriding the default worker count.
func WithConcurrency(n int) Option {
	return func(p *Pipeline) {
		if n > 0 {
			p.concurrency = n
		}
	}
}

// WithConcurrency allows overriding the default worker count.
func WithLogger(logger *zerolog.Logger) Option {
	return func(p *Pipeline) {
		p.logger = logger
	}
}

// WithFilters allows passing multiple filters (FileSizeFilter, TextFileOnlyFilter).
func WithFilters(filters ...FileFilter) Option {
	return func(p *Pipeline) {
		p.filters = append(p.filters, filters...)
	}
}

// Filter processes the input channel through the configured filters concurrently.
// It returns a new channel containing only the files that passed all filters.
func (p *Pipeline) Filter(ctx context.Context, inputPaths []string) chan string {
	files := streamAllowedFiles(ctx, inputPaths, ignoreFiles, getCustomGlobIgnoreRules(), p.logger)

	// Output channel buffer size matches concurrency for optimal flow
	filteredFiles := make(chan string, p.concurrency)
	var wg sync.WaitGroup

	// Spin up workers based on the configured concurrency
	for i := 0; i < p.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}

			// Iterate over incoming paths
			for path := range files {
				keep := true

				// Apply all configured filters
				for _, filter := range p.filters {
					if filter.FilterOut(path) {
						keep = false
						break
					}
				}

				if keep {
					select {
					case filteredFiles <- path:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// Closer routine
	go func() {
		wg.Wait()
		close(filteredFiles)
	}()
	return filteredFiles
}
