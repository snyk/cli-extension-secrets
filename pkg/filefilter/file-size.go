//nolint:ireturn // Returns interface because implementation is private
package filefilter

const (
	_MaxFileSize = 5000000 // 50 MB
)

type fileSizeFilter struct{}

func FileSizeFilter() FileFilter {
	return &fileSizeFilter{}
}

func (fileSizeFilter) FilterOut(file File) bool {
	if file.Info() == nil {
		return true
	}
	if file.Info().Size() == 0 {
		return true
	}
	if file.Info().Size() > _MaxFileSize {
		return true
	}
	return false
}
