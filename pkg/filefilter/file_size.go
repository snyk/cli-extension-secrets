package filefilter

import (
	"os"

	"github.com/rs/zerolog"
)

const (
	_MaxFileSize = 50_000_000 // 50 MB
)

type fileSizeFilter struct {
	logger *zerolog.Logger
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
		return true
	}
	size := info.Size()
	if size == 0 || size > _MaxFileSize {
		return true
	}
	return false
}
