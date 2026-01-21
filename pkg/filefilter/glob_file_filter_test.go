package filefilter_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

func Test_ExpandExcludeNames(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    []string
		wantErr error
	}{
		{
			name:  "Empty input returns empty slice",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "Standard directory and file",
			input: []string{"node_modules", "config.json"},
			want: []string{
				"**/node_modules", "**/node_modules/**",
				"**/config.json", "**/config.json/**",
			},
		},
		{
			name:  "Noisy whitespace and empty entries",
			input: []string{"  item1 ", "", " item2  "},
			want: []string{
				"**/item1", "**/item1/**",
				"**/item2", "**/item2/**",
			},
		},
		{
			name:    "Slash in input returns error",
			input:   []string{"dir/subdir"},
			want:    nil,
			wantErr: filefilter.ErrPathNotAllowed,
		},
		{
			name:    "Windows backslash returns error",
			input:   []string{"target\\debug"},
			want:    nil,
			wantErr: filefilter.ErrPathNotAllowed,
		},
		{
			name:    "Path traversal returns error",
			input:   []string{"../etc"},
			want:    nil,
			wantErr: filefilter.ErrPathNotAllowed,
		},
		{
			name:  "Hidden files work without slashes",
			input: []string{".env"},
			want:  []string{"**/.env", "**/.env/**"},
		},
		{
			name:  "Skips pure whitespace entries",
			input: []string{"   ", "\t"},
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filefilter.ExpandExcludeNames(tt.input)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ExpandExcludeNames() error = %v, wantErr %v", err, tt.wantErr)
				}
				if got != nil {
					t.Errorf("ExpandExcludeNames() expected nil result on error, got %v", got)
				}
				return
			}

			if err != nil {
				t.Errorf("ExpandExcludeNames() unexpected error: %v", err)
				return
			}
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExpandExcludeNames() \n got = %v \n want = %v", got, tt.want)
			}
		})
	}
}
