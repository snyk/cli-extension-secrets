package filefilter

import (
	"path/filepath"
	"slices"
)

type ExtensionFilter struct {
	extensions []string
}

func NewExtensionFilter() Filter {
	ef := &ExtensionFilter{}
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

func (ef *ExtensionFilter) FilterOut(file LocalFile) bool {
	extension := filepath.Ext(file.Path)
	return slices.Contains(ef.extensions, extension)
}
