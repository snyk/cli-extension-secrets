package filefilter

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func ReadFileHeader(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Get file size
	stat, statErr := f.Stat()
	if statErr != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", statErr)
	}
	size := stat.Size()

	// Determine the smaller of n or the actual file size
	bytesToRead := min(n, size)
	// Handle 0-byte files
	if bytesToRead == 0 {
		return []byte{}, nil
	}

	// Allocate the exact buffer size
	buf := make([]byte, int(bytesToRead))
	nr, err := f.Read(buf)
	// We only return an error if it's *not* io.EOF
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read bytes: %w", err)
	}
	// Return the actual bytes read (buf[:nr])
	return buf[:nr], nil
}
