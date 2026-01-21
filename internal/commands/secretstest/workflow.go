package secretstest

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	FeatureFlagIsSecretsEnabled = "internal_snyk_feature_flag_is_secrets_enabled" //nolint:gosec // config key
)

var WorkflowID = workflow.NewWorkflowIdentifier("secrets.test")

func RegisterWorkflows(e workflow.Engine) error {
	flagSet := GetSecretsTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(flagSet)

	if _, err := e.Register(WorkflowID, c, SecretsWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}

	config_utils.AddFeatureFlagToConfig(e, FeatureFlagIsSecretsEnabled, "isSecretsEnabled")

	return nil
}

func SecretsWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	ctx := context.Background()
	ctx = cmdctx.WithIctx(ctx, ictx)

	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	u := NewUI(ictx)
	u.SetTitle(TitleValidating)
	defer u.Clear()

	if !config.GetBool(FeatureFlagIsSecretsEnabled) {
		return nil, cli_errors.NewFeatureNotEnabledError("User not allowed to run without feature flag.")
	}

	if config.IsSet(FlagReport) {
		return nil, cli_errors.NewFeatureUnderDevelopmentError("Flag --report is not yet supported.")
	}

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, cli_errors.NewValidationFailureError("No org provided.")
	}

	err := validateFlagsConfig(config)
	if err != nil {
		return nil, cli_errors.NewInvalidFlagOptionError(err.Error(), snyk_errors.WithCause(err))
	}

	inputPaths := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(inputPaths) != 1 {
		return nil, cli_errors.NewValidationFailureError("Only one input path is accepted.")
	}

	inputPath, err := filepath.Abs(inputPaths[0])
	if err != nil {
		logger.Error().Err(err).Msg("could not get absolute path for: " + inputPaths[0])
		return nil, cli_errors.NewGeneralSecretsFailureError("Unable to get absolute path")
	}

	repoURL, gitRootDir, err := findGitRoot(inputPath)
	if err != nil {
		logger.Err(err).Str("dir", gitRootDir).Str("repoURL", repoURL).Msg("could not determine common repo root")
	}

	inputPathRelativeToGitRoot, err := computeRelativeInput(inputPath, gitRootDir)
	if err != nil {
		logger.Err(err).Str("inputPathRelativeToGitRoot", inputPathRelativeToGitRoot).Msg("could not determine common repo root")
	}

	excludeGlobs, err := parseExcludeFlag(config)
	if err != nil {
		return nil, cli_errors.NewInvalidFlagOptionError(err.Error(), snyk_errors.WithCause(err))
	}

	args := &CommandArgs{
		InvocationContext: ictx,
		UserInterface:     u,
		OrgID:             orgID,
		RootFolderID:      inputPathRelativeToGitRoot,
		RepoURL:           repoURL,
		GetClients:        NewWorkflowClients,
		Excludes:          excludeGlobs,
	}
	c, err := NewCommand(args)
	if err != nil {
		logger.Error().Err(err).Msg("could not initialize command")
		return nil, cli_errors.NewGeneralSecretsFailureError(UnableToInitializeError)
	}

	logger.Info().Str("inputPath", inputPath).Msg("Running secrets workflow...")
	output, err := c.RunWorkflow(ctx, inputPath)
	if err != nil {
		logger.Error().Err(err).Msg("workflow execution failed")
		return nil, cli_errors.NewGeneralSecretsFailureError("workflow execution failed")
	}

	return output, nil
}
