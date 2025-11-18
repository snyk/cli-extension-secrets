//nolint:ireturn // Returns interface because implementation is private
package filefilter

import (
	"path/filepath"
	"slices"
)

type extensionFilter struct {
	extensions []string
}

func FileExtensionFilter() FileFilter {
	ef := &extensionFilter{}
	ef.extensions = []string{
		".bmp",
		".dcm",
		".gif",
		".iff",
		".jpg",
		".jpeg",
		".pbm",
		".pict",
		".pic",
		".pct",
		".pcx",
		".png",
		".psb",
		".psd",
		".pxr",
		".raw",
		".tga",
		".tiff",
		".svg",
	}
	return ef
}

func (ef *extensionFilter) FilterOut(file File) bool {
	extension := filepath.Ext(file.Path())
	return slices.Contains(ef.extensions, extension)
}
