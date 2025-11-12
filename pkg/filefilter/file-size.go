package filefilter

const (
	_MAX_FILE_SIZE = 5000000 // 50 MB
)

type FileSizeFilter struct {
}

func NewFileSizeFilter() Filter {
	return &FileSizeFilter{}
}

func (FileSizeFilter) FilterOut(file LocalFile) bool {
	if file.Info.Size() == 0 {
		return true
	}
	if file.Info.Size() > _MAX_FILE_SIZE {
		return true
	}
	return false
}
