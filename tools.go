//go:build tools

package main

import (
	_ "github.com/golang/mock/mockgen"
	_ "github.com/snyk/jwt-cli/cmd/jwt"
	_ "github.com/vektra/mockery/v2"
	_ "github.com/zricethezav/gitleaks/v8"
	_ "golang.org/x/pkgsite/cmd/pkgsite"
)
