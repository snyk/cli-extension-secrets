package filefilter

import (
	"os"
	"sync/atomic"

	"github.com/rs/zerolog"
)

const (
	_MaxFileSize = 1_000_000 // 1 MB
)

type fileSizeFilter struct {
	logger        *zerolog.Logger
	filteredFiles atomic.Int64
}

//nolint:ireturn // Returns interface because implementation is private
func FileSizeFilter(logger *zerolog.Logger) FileFilter {
	return &fileSizeFilter{
		logger: logger,
	}
}

func (f *fileSizeFilter) FilterOut(path string) bool {
	// Get file size
	info, statErr := os.Stat(path)
	if statErr != nil {
		// Filters are enforced, we should exclude any files that we can't classify
		f.logger.Error().Msgf("failed to get file stats: %v", statErr)
		f.filteredFiles.Add(1)
		return true
	}
	size := info.Size()
	if size == 0 || size > _MaxFileSize {
		f.filteredFiles.Add(1)
		return true
	}
	return false
}

func (f *fileSizeFilter) RecordMetrics(analytics Analytics) {
	if analytics == nil {
		return
	}
	count := f.filteredFiles.Load()
	analytics.RecordSizeFiltered(int(count))
}
