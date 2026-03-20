package secretstest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// sanitizePath strips double-quote characters from a filesystem path.
// On Windows, " is an invalid path character that commonly appears when
// the shell misinterprets a trailing backslash-quote (e.g. "C:\path\").
// On Unix, " is a valid path character, so the path is returned unchanged.
func sanitizePath(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	return strings.ReplaceAll(path, `"`, "")
}

func isFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("failed to stat %s: %w", path, err)
	}

	return !info.IsDir(), nil
}

func getDir(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat %s: %w", path, err)
	}

	if info.IsDir() {
		return path, nil
	}

	return filepath.Dir(path), nil
}
