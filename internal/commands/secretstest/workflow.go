package secretstest

import (
	"context"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
)

var WorkflowID = workflow.NewWorkflowIdentifier("secrets.test")

func RegisterWorkflows(e workflow.Engine) error {
	flagSet := GetSecretsTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(flagSet)

	if _, err := e.Register(WorkflowID, c, SecretsWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}

	// TODO: add the feature flag required to gate the secrets test feature, similar to below:
	// https://github.com/snyk/cli-extension-os-flows/blob/d279e5c83acaf21f3c6a2ba4849ffe8e274b577b/internal/commands/ostest/workflow.go#L70-L76
	return nil
}

func SecretsWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	// TODO: check the feature flag for secrets and return some error if not enabled (?)
	// https://github.com/snyk/cli-extension-os-flows/blob/d279e5c83acaf21f3c6a2ba4849ffe8e274b577b/internal/commands/ostest/workflow.go#L133-L135

	// TODO: validate the flags
	// 1. project related flags can only be used in combination with --report
	// 2. here we can also return an error if a flag is unsupported in closed beta
	// https://github.com/snyk/cli-extension-iac/blob/main/internal/commands/iactest/iactest.go#L72
	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("no org provided")
		return nil, nil // TODO: error handling
	}

	// TODO: determine the input paths (default is .)
	// should we be able to scan multiple inputs?
	args := os.Args[1:]
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}
	inputPaths := DetermineInputPaths(args, cwd)

	// TODO: setup the clients
	// 1. for the upload api
	// 2. for the test-api-shim
	uploadClient, err := upload.NewClient(ictx)
	if err != nil {
		return nil, fmt.Errorf("failed to create upload client: %w", err)
	}
	testShimClient, err := testshim.NewClient(ictx)
	if err != nil {
		return nil, fmt.Errorf("failed to create test shim client: %w", err)
	}

	// TODO: here we need to pass all required clients (uploadapi, testshim)
	// better to create a wrapper struct with all the required clients
	ctx := context.Background()
	err = runWorkflow(ctx, testShimClient, uploadClient, inputPaths, logger)
	if err != nil {
		return nil, err // TODO: error handling
	}

	return nil, nil
}

//nolint:unparam // TODO: remove this after adding the implem
func runWorkflow(
	_ context.Context,
	_ *testshim.Client,
	_ *upload.Client,
	_ []string,
	logger *zerolog.Logger,
) error {
	logger.Debug().Msg("running secrets test workflow...")
	// TODO: create the revision via the upload client
	// TODO: populate the subject struct (which is generated type from data-schema?)
	// TODO: run the test on the subject via the testshim client (start the test, poll the test, get results)
	// https://snyksec.atlassian.net/wiki/spaces/RD/pages/3242262614/Test+API+for+Risk+Score#Solution
	// TODO: handle the output (use the module provided by IDE/CLI team that works with data layer findings?)
	return nil
}
