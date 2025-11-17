package filefilter

import (
	"io"
	"os"
)

// File represents a file that can be filtered
type File interface {
	// Path returns the file's path
	Path() string
	Info() os.FileInfo
	// ReadHeader reads the first n bytes of the file
	ReadHeader(n int64) ([]byte, error)
}

type LocalFile struct {
	path string
	info os.FileInfo
}

func NewLocalFile(path string, info os.FileInfo) *LocalFile {
	return &LocalFile{
		path: path,
		info: info,
	}
}

func (lf *LocalFile) Path() string {
	return lf.path
}

func (lf *LocalFile) Info() os.FileInfo {
	return lf.info
}

func (lf *LocalFile) ReadHeader(n int64) ([]byte, error) {
	f, err := os.Open(lf.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Get file size
	var size int64
	if lf.Info() != nil {
		size = lf.info.Size()
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
