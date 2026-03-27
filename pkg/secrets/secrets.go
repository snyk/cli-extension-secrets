// Package secrets is the entry point for the secrets workflow.
package secrets

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/commands/secretstest"
)

// Init registers all secrets-related workflows with the given engine.
func Init(e workflow.Engine) error {
	// Register the "secrets test" command
	err := secretstest.RegisterWorkflows(e)
	if err != nil {
		return fmt.Errorf("failed to register secrets test workflows: %w", err)
	}
	return nil
}
