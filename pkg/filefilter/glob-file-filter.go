//nolint:ireturn // Returns interface because implementation is private
package filefilter

import (
	gitignore "github.com/sabhiram/go-gitignore"
)

var IgnoredExtensionsGlob = []string{
	"*.bmp", "*.dcm", "*.gif", "*.iff",
	"*.jpg", "*.jpeg", "*.pbm", "*.pict",
	"*.pic", "*.pct", "*.pcx", "*.png",
	"*.psb", "*.psd", "*.pxr", "*.raw",
	"*.tga", "*.tiff", "*.svg",
}

var IgnoreGenericFilesGlob = []string{
	// Go Modules & Build
	"go.mod",
	"go.sum",
	"go.work",
	"go.work.sum",

	// Go Vendor
	"vendor/modules.txt",

	"vendor/github.com/",
	"vendor/golang.org/x/",
	"vendor/google.golang.org/",
	"vendor/gopkg.in/",
	"vendor/istio.io/",
	"vendor/k8s.io/",
	"vendor/sigs.k8s.io/",

	// Node/JavaScript/General Web
	"node_modules/",
	"bower_components/",

	// Lockfiles
	"deno.lock",
	"npm-shrinkwrap.json",
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",

	// Vendored JS Libraries
	"angular*.js",
	"angular*.js.map",
	"bootstrap*.js",
	"bootstrap*.js.map",
	// Covers jquery and jquery-ui
	"jquery*.js",
	"jquery*.js.map",
	"plotly*.js",
	"plotly*.js.map",
	// Covers swagger-ui and swaggerui
	"swagger-ui*.js",
	"swagger-ui*.js.map",

	// Python
	// Lockfiles
	"Pipfile.lock",
	"poetry.lock",

	// Virtual Envs
	"venv/lib/",
	"venv/lib64/",
	"env/lib/",
	"env/lib64/",
	"virtualenv/lib/",
	"virtualenv/lib64/",

	// System Libs
	"lib/python*/",
	"lib64/python*/",
	"python/*/lib/",
	"python/*/lib64/",

	// Dist Info
	"*.dist-info/",

	// Ruby
	"vendor/bundle/",
	"vendor/ruby/",
	"*.gem",

	// Java/Gradle/Maven
	"gradle.lockfile",
	"gradlew",
	"gradlew.bat",
	"mvnw",
	"mvnw.cmd",
	".mvn/wrapper/MavenWrapperDownloader.java",
	"verification-metadata.xml",

	// Configs & Metadata
	".git/",
	".gitleaks/",
	"gitleaks.toml",
	"javascript.json",
	"Database.refactorlog",
}

type globFileFilter struct {
	globPatternMatcher *gitignore.GitIgnore
}

func GlobFileFilter(initialRules []string) FileFilter {
	totalLen := len(IgnoredExtensionsGlob) + len(IgnoreGenericFilesGlob) + len(initialRules)
	finalRules := make([]string, 0, totalLen)

	finalRules = append(finalRules, IgnoredExtensionsGlob...)
	finalRules = append(finalRules, IgnoreGenericFilesGlob...)
	finalRules = append(finalRules, initialRules...)

	return &globFileFilter{
		globPatternMatcher: gitignore.CompileIgnoreLines(finalRules...),
	}
}

func (gf *globFileFilter) FilterOut(file File) bool {
	return gf.globPatternMatcher.MatchesPath(file.Path())
}
