package secretstest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

func DetermineInputPaths(args []string, cwd string) []string {
	paths := []string{}
	for _, arg := range args {
		isCommand := slices.Contains([]string{"secrets", "test"}, arg)
		isFlag := strings.HasPrefix(arg, "-")
		if !isCommand && !isFlag {
			paths = append(paths, arg)
		}
	}
	if len(paths) == 0 {
		paths = append(paths, cwd)
	}
	return paths
}

type LocalFile struct {
	Path string
	Info os.FileInfo
}

func FindAllFiles(paths []string) ([]LocalFile, error) {
	allFiles := make([]LocalFile, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			// Skip paths that don't exist
			if os.IsNotExist(err) {
				continue
			}

			return nil, fmt.Errorf("failed to stat input path %q: %w", path, err)
		}
		if !info.IsDir() {
			allFiles = append(allFiles, LocalFile{
				Path: path,
				Info: info,
			})
			continue
		}
		// Walk this directory and collect files
		walkErr := filepath.WalkDir(path, func(walkPath string, d fs.DirEntry, err error) error {
			// Check for an error passed by WalkDir (e.g., permission denied)
			if err != nil {
				return fmt.Errorf("error accessing path %q during walk: %w", walkPath, err)
			}
			// We only want files, so if it's a directory, we skip adding it
			if d.IsDir() {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("failed to get file info for %q: %w", walkPath, err)
			}

			allFiles = append(allFiles, LocalFile{
				Path: walkPath,
				Info: info,
			})
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("failed to walk directory %q: %w", path, walkErr)
		}
	}
	return allFiles, nil
}

func ToFileFilterList(files []LocalFile) []filefilter.File {
	ffList := make([]filefilter.File, len(files))
	for i, file := range files {
		// Manually copy the fields to create the new type
		ffList[i] = filefilter.NewLocalFile(file.Path, file.Info)
	}
	return ffList
}
