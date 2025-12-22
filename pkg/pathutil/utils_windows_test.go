//go:build windows

package pathutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToRelativeUnixPathWindows(t *testing.T) {
	tests := []struct {
		name         string
		rootFolderID string
		absolutePath string
		expected     string
	}{
		{"file in src folder", `C:\Users\dev\project`, `C:\Users\dev\project\src\main.go`, `src/main.go`},
		{"file in config folder", `C:\Users\dev\project`, `C:\Users\dev\project\config\db.yml`, `config/db.yml`},
		{"file at root", `C:\Users\dev\project`, `C:\Users\dev\project\secrets.env`, `secrets.env`},
		{"deeply nested file", `C:\project`, `C:\project\a\b\c\d\file.txt`, `a/b/c/d/file.txt`},
		{"different drive", `D:\work`, `D:\work\src\app\index.js`, `src/app/index.js`},
		{"UNC path", `\\server\share\project`, `\\server\share\project\src\file.go`, `src/file.go`},
		{"same as root", `C:\Users\dev\project`, `C:\Users\dev\project`, `.`},
		{"root with trailing slash", `C:\Users\dev\project\`, `C:\Users\dev\project\src\file.go`, `src/file.go`},
		{"relative base dir", `project`, `project\src\main.go`, `src/main.go`},
		{"relative base with dot prefix", `.\project`, `.\project\config\app.yml`, `config/app.yml`},
		{"relative deeply nested", `myapp\code`, `myapp\code\pkg\utils\file.go`, `pkg/utils/file.go`},
		{"relative same as root", `project`, `project`, `.`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ToRelativeUnixPath(tt.rootFolderID, tt.absolutePath)

			require.NoError(t, err, "unexpected error")
			assert.Equal(t, tt.expected, result)
		})
	}
}
