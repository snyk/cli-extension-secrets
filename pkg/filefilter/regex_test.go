//nolint:testpackage // whitebox
package filefilter

import "testing"

func TestRegexPathFilter_FilterOut(t *testing.T) {
	filter := RegexPathFilter()

	testCases := []struct {
		name string // Description
		path string // File path
		want bool   // Expected result (true = filter out, false = keep)
	}{
		// Cases that SHOULD be filtered out
		// Go
		{"Go mod", "go.mod", true},
		{"Go sum", "go.sum", true},
		{"Go work", "go.work", true},
		{"Go work sum", "go.work.sum", true},
		{"Go vendor list", "vendor/modules.txt", true},
		{"Nested Go vendor list", "src/vendor/modules.txt", true},
		{"Go vendor pkg", "vendor/github.com/gorilla/mux", true},
		{"Go vendor pkg nested", "vendor/golang.org/x/net/context.go", true},
		// Node/JS
		{"Node modules", "node_modules/react/index.js", true},
		{"Nested Node modules", "src/api/node_modules/lodash.js", true},
		{"Package lock", "package-lock.json", true},
		{"Nested Yarn lock", "src/client/yarn.lock", true},
		{"PNPM lock", "pnpm-lock.yaml", true},
		{"Bower components", "bower_components/jquery/jquery.js", true},
		{"Vendored jQuery", "assets/js/jquery.min.js", true},
		{"Vendored Bootstrap", "lib/bootstrap.js.map", true},
		{"Vendored Angular", "dist/angular.js", true},
		// Python
		{"Pipfile lock", "Pipfile.lock", true},
		{"Nested Poetry lock", "backend/poetry.lock", true},
		{"Venv lib", "venv/lib/python3.10/site-packages/foo.py", true},
		{"Virtualenv lib", "virtualenv/lib64/python3.9/site-packages/bar.py", true},
		{"Dist-info", "env/lib/python3.8/site-packages/requests-2.25.1.dist-info/METADATA", true},
		// Ruby
		{"Ruby vendor bundle", "vendor/bundle/ruby/2.7.0/gems/some_gem.rb", true},
		{"Ruby Gem file", "my_gem-1.2.3.gem", true},
		// Build Tools & VCS
		{"Gradle lockfile", "gradle.lockfile", true},
		{"Git folder", ".git", true},
		{"Nested Git folder", "src/component/.git", true},
		{"Gradle wrapper", "gradlew", true},
		{"Gradle wrapper bat", "gradlew.bat", true},
		{"Maven wrapper", "mvnw", true},
		{"Maven wrapper cmd", "mvnw.cmd", true},
		{"Maven wrapper source", ".mvn/wrapper/MavenWrapperDownloader.java", true},
		// Config/Misc
		{"Gitleaks config", "gitleaks.toml", true},
		{"Nested Gitleaks config", ".config/gitleaks.toml", true},
		{"Gitleaks folder", ".gitleaks/my-report.json", true},
		{"JS config", "javascript.json", true},
		{"Nested JS config", "config/javascript.json", true},
		{"Verification metadata", "verification-metadata.xml", true},
		{"DB refactor log", "Database.refactorlog", true},

		// Cases that SHOULD NOT be filtered out
		{"Go main", "main.go", false},
		{"Go internal pkg", "internal/server/server.go", false},
		{"Go test file", "main_test.go", false},
		{"Readme", "README.md", false},
		{"JS source", "src/index.js", false},
		{"CSS file", "static/css/styles.css", false},
		{"Python source", "app/models.py", false},
		{"Dockerfile", "Dockerfile", false},
		{"Similar name 1", "not-go.mod.txt", false},
		{"Similar name 2", "a/b/c.gem.bak", false},
		{"Similar name 3", "docs/javascript.json.md", false},
		{"Non-vendor path", "my_vendor/main.go", false},
		{"Non-vendored JS", "src/utils/my-angular-helper.js", false},
	}

	// Run tests
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			file := NewLocalFile(tt.path, nil)
			got := filter.FilterOut(file)

			if got != tt.want {
				t.Errorf("FilterOut(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
