package filefilter

import (
	"errors"
	"strings"
)

// ErrPathNotAllowed is returned when an exclude rule contains a path separator.
var ErrPathNotAllowed = errors.New("paths are not allowed in exclude rules")

// ignoredExtensionsGlob lists file extensions that are never useful for secrets scanning
// (media, fonts, archives, binaries, etc.).
var ignoredExtensionsGlob = []string{
	// Media file extensions.
	"*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.tiff",
	"*.tif", "*.ico", "*.svg", "*.webp", "*.psd", "*.psb",
	"*.pxr", "*.xcf", "*.heic", "*.heif", "*.avif", "*.ai",
	"*.cr2", "*.nef", "*.orf", "*.dwg", "*.dxf", "*.dcm",
	"*.iff", "*.pbm", "*.pict", "*.pic", "*.pct", "*.pcx",
	"*.raw", "*.tga",
	// Audio/video.
	"*.mp3", "*.wav", "*.aac", "*.flac", "*.ogg", "*.m4a",
	"*.wma", "*.mp4", "*.mov", "*.avi", "*.mkv", "*.webm",
	"*.flv", "*.wmv",
	// Fonts.
	"*.ttf", "*.otf", "*.woff", "*.woff2", "*.eot",
	// Generated files.
	"*.map", "*.min.css",
	// Crash data.
	"*.dmp", "*.stackdump",
	// Python/Ruby/Java compiled or serialized artifacts.
	"*.pyc", "*.pyo", "*.npy", "*.npz", "*.pkl", "*.gem", "*.class",
	// Signature files.
	"*.md5", "*.sha1", "*.sha256", "*.sha512",
	// Compressed files. Update once we add support for scanning archives.
	"*.zip", "*.tar", "*.gz", "*.tgz", "*.rar", "*.7z",
	"*.bz2", "*.xz", "*.zst", "*.iso", "*.cab", "*.jar",
	"*.war", "*.ear",
	// Binaries. Update once we add support for scanning binaries.
	"*.pdf", "*.epub", "*.mobi", "*.wasm", "*.exe", "*.dll",
	"*.so", "*.dylib", "*.bin", "*.elf",
}

// ignoreGenericFilesGlob lists specific file names and directories (lockfiles, vendored
// dependencies, tooling metadata) that are never useful for secrets scanning.
var ignoreGenericFilesGlob = []string{
	// Generated files.
	"javascript.json", "Database.refactorlog",
	// Filesystem files.
	".DS_Store", "Thumbs.db",
	// Node/JavaScript.
	"node_modules/", "bower_components/", "package-lock.json", "yarn.lock",
	"pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "bun.lock", "deno.lock",
	"angular*.js", "angular*.js.map", "bootstrap*.js", "bootstrap*.js.map",
	"jquery*.js", "jquery*.js.map", "plotly*.js", "plotly*.js.map",
	"swagger-ui*.js", "swagger-ui*.js.map",
	// Python.
	"poetry.lock", "Pipfile.lock", "uv.lock",
	"venv/lib/", "venv/lib64/", "env/lib/", "env/lib64/",
	"virtualenv/lib/", "virtualenv/lib64/", "lib/python*/", "lib64/python*/",
	"python/*/lib/", "python/*/lib64/", "*.dist-info/",
	// PHP.
	"composer.lock",
	// Go.
	"go.mod", "go.sum", "go.work", "go.work.sum", "Gopkg.lock", "glide.lock",
	"vendor/modules.txt", "vendor/github.com/", "vendor/golang.org/x/",
	"vendor/google.golang.org/", "vendor/gopkg.in/", "vendor/istio.io/",
	"vendor/k8s.io/", "vendor/sigs.k8s.io/",
	// Rust.
	"Cargo.lock",
	// Dart/Flutter.
	"pubspec.lock",
	// Elixir.
	"mix.lock",
	// Ruby.
	"Gemfile.lock", "vendor/bundle/", "vendor/ruby/",
	// Java/Gradle/Maven.
	"gradle.lockfile", "verification-metadata.xml", "gradlew",
	"gradlew.bat", "mvnw", "mvnw.cmd", ".mvn/wrapper/MavenWrapperDownloader.java",
	// Terraform.
	".terraform.lock.hcl",
	// Git related.
	".git/", ".gitleaks/", gitIgnoreFile, "gitleaks.toml", ".gitleaksignore", ".betterleaksignore", "LICENSE",
}

func getCustomGlobIgnoreRules() []string {
	totalLen := len(ignoredExtensionsGlob) + len(ignoreGenericFilesGlob)
	customRules := make([]string, 0, totalLen)

	customRules = append(customRules, ignoredExtensionsGlob...)
	customRules = append(customRules, ignoreGenericFilesGlob...)
	return customRules
}

// ExpandExcludeNames validates and converts user-provided names into global glob patterns.
// It enforces the rule that inputs must be basenames (example: "node_modules"), not paths.
func ExpandExcludeNames(names []string) ([]string, error) {
	patterns := make([]string, 0, len(names)*2)
	for _, entry := range names {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}

		if strings.ContainsAny(trimmed, "/\\") {
			return nil, ErrPathNotAllowed
		}

		patterns = append(patterns,
			"**/"+trimmed,
			"**/"+trimmed+"/**",
		)
	}
	return patterns, nil
}
