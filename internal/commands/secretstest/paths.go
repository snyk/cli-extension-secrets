package secretstest

import (
	"slices"
	"strings"
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
