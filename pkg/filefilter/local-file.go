package filefilter

import (
	"io"
	"os"
)

type LocalFile struct {
	Path string
	Info os.FileInfo
}

func (lf *LocalFile) ReadHeader(n int64) ([]byte, error) {
	f, err := os.Open(lf.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Get file size
	var size int64
	if lf.Info != nil {
		size = lf.Info.Size()
	} else {
		// Fallback if lf.Info is nil: get stats from the file handle
		stat, err := f.Stat()
		if err != nil {
			return nil, err
		}
		size = stat.Size()
	}

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
	if err != nil && err != io.EOF {
		return nil, err
	}
	// Return the actual bytes read (buf[:nr])
	return buf[:nr], nil
}
