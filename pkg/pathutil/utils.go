package pathutil

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"
)

// TODO: This could potentially be moved to GAF as multiple other repos across Snyk
// redefine the same function over and over, e.g. code-client-go:
// https://github.com/snyk/code-client-go/blob/943c98b9c7009386d2950c594df19f87bc875642/internal/util/path.go#L29.
func ToRelativeUnixPath(baseDir, absoluteFilePath string) (string, error) {
	relativePath, err := filepath.Rel(baseDir, absoluteFilePath)
	if err != nil {
		relativePath = absoluteFilePath
		if baseDir != "" {
			errMsg := fmt.Sprint("could not get relative path for file: ", absoluteFilePath, " and root path: ", baseDir)
			return "", errors.Wrap(err, errMsg)
		}
	}

	relativePath = filepath.ToSlash(relativePath) // treat all paths as unix paths
	return relativePath, nil
}
