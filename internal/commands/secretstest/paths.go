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

// commonBaseDir returns a single directory that contains every input path.
// A directory input contributes itself; a file input contributes its parent
// directory. When more than one path is provided, their nearest common
// ancestor directory is returned. This base directory is used both to upload
// the files as a single revision and to anchor their paths relative to the
// repository root.
func commonBaseDir(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", fmt.Errorf("no paths provided")
	}

	dirs := make([]string, 0, len(paths))
	for _, p := range paths {
		dir, err := getDir(p)
		if err != nil {
			return "", err
		}
		dirs = append(dirs, dir)
	}

	base := dirs[0]
	for _, dir := range dirs[1:] {
		base = commonAncestor(base, dir)
	}

	return base, nil
}

// commonAncestor returns the deepest directory that is a prefix of both a and
// b. Both inputs are expected to be cleaned absolute paths.
func commonAncestor(a, b string) string {
	if a == b {
		return a
	}

	sep := string(filepath.Separator)
	aParts := strings.Split(filepath.ToSlash(a), "/")
	bParts := strings.Split(filepath.ToSlash(b), "/")

	common := make([]string, 0, len(aParts))
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		if aParts[i] != bParts[i] {
			break
		}
		common = append(common, aParts[i])
	}

	joined := strings.Join(common, "/")
	if joined == "" {
		// On POSIX the shared root collapses to "/"; on Windows there may be
		// no shared root (e.g. different drive letters), in which case the
		// caller still gets a usable, if broad, base directory.
		return sep
	}

	return filepath.FromSlash(joined)
}
