package filefilter

/*
This file contains regex patterns derived from the gitleaks project.
https://github.com/gitleaks/gitleaks

The gitleaks project is licensed under the MIT License:

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import "regexp"

type regexFilter struct {
	patterns []*regexp.Regexp
}

func RegexPathFilter() FileFilter {
	rf := &regexFilter{}
	rf.patterns = []*regexp.Regexp{
		regexp.MustCompile(`go\.(?:mod|sum|work(?:\.sum)?)$`), // Go module files (mod, sum, work)
		regexp.MustCompile(`(?:^|/)vendor/modules\.txt$`),     // Go vendor modules list
		regexp.MustCompile(`(?:^|/)vendor/(?:github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(?:/.*)?$`), // Go vendored dependency folders
		regexp.MustCompile(`(?:^|/)node_modules(?:/.*)?$`),                                                                           // Node.js modules folder
		regexp.MustCompile(`(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$`),              // JavaScript lock files
		regexp.MustCompile(`(?:^|/)bower_components(?:/.*)?$`),                                                                       // Bower components folder
		regexp.MustCompile(`(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$`), // Common vendored JS libraries
		regexp.MustCompile(`(?:^|/)(?:Pipfile|poetry)\.lock$`),                                                                       // Python lock files
		regexp.MustCompile(`(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$`),                                                    // Python virtual environment library folder
		regexp.MustCompile(`(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\.\d{1,2})+|python/[23](?:\.\d{1,2})+/lib(?:64)?)(?:/.*)?$`),       // Python system library folder
		regexp.MustCompile(`(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$`),                                                     // Python package distribution info
		regexp.MustCompile(`(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$`),                                                                // Ruby vendored gems (bundle, ruby)
		regexp.MustCompile(`\.gem$`),                                             // Ruby Gem files
		regexp.MustCompile(`(?:^|/)gradle\.lockfile$`),                           // Gradle lockfile
		regexp.MustCompile(`(?:^|/)\.git$`),                                      // Git repository folder
		regexp.MustCompile(`(?:^|/)\.gitleaks(?:/.*)?$`),                         // Gitleaks folder
		regexp.MustCompile(`(?:^|/)gradlew(?:\.bat)?$`),                          // Gradle wrapper script
		regexp.MustCompile(`(?:^|/)mvnw(?:\.cmd)?$`),                             // Maven wrapper script
		regexp.MustCompile(`(?:^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$`), // Maven wrapper downloader source
		regexp.MustCompile(`gitleaks\.toml`),                                     // Gitleaks configuration file
		regexp.MustCompile(`(?:^|/)javascript\.json$`),                           // javascript.json configuration file
		regexp.MustCompile(`verification-metadata\.xml`),                         // Verification metadata XML
		regexp.MustCompile(`Database\.refactorlog`),                              // Database refactor log
	}
	return rf
}

func (rf *regexFilter) FilterOut(file File) bool {
	for _, pattern := range rf.patterns {
		if pattern.MatchString(file.Path()) {
			return true
		}
	}
	return false
}
