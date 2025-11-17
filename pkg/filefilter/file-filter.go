package filefilter

type FileFilter interface {
	FilterOut(File) bool
}

func Filter(files []File, filters ...FileFilter) []File {
	results := make([]File, 0, len(files))
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
