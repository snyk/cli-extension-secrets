package filefilter

const (
	_MAX_FILE_SIZE = 5000000 // 50 MB
)

type fileSizeFilter struct {
}

func FileSizeFilter() FileFilter {
	return &fileSizeFilter{}
}

func (fileSizeFilter) FilterOut(file LocalFile) bool {
	if file.Info.Size() == 0 {
		return true
	}
	if file.Info.Size() > _MAX_FILE_SIZE {
		return true
	}
	return false
}
