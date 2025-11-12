package filefilter

type Filter interface {
	FilterOut(LocalFile) bool
}

type FileFilter struct {
	filters []Filter
}

func NewFileFilter() *FileFilter {
	ff := &FileFilter{}
	ff.filters = append(ff.filters, NewFileSizeFilter(), NewExtensionFilter(), NewRegexFilter(), NewTextFileOnly())
	return ff
}

func (ff *FileFilter) Filter(files []LocalFile) []LocalFile {
	results := make([]LocalFile, 0, len(files))
	for _, file := range files {
		shouldFilterOut := false
		for _, filter := range ff.filters {
			if filter.FilterOut(file) {
				shouldFilterOut = true
				break
			}
		}

		if !shouldFilterOut {
			results = append(results, file)
		}
	}
	return results
}
