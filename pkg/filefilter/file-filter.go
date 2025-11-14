package filefilter

type FileFilter interface {
	FilterOut(LocalFile) bool
}

func Filter(files []LocalFile, filters ...FileFilter) []LocalFile {
	results := make([]LocalFile, 0, len(files))
	for _, file := range files {
		shouldFilterOut := false
		for _, filter := range filters {
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
