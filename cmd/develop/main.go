package main

import (
	"log"

	"github.com/snyk/go-application-framework/pkg/devtools"

	"github.com/snyk/cli-extension-secrets/pkg/secrets"
)

func main() {
	cmd, err := devtools.Cmd(secrets.Init)
	if err != nil {
		log.Fatal(err)
	}
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
