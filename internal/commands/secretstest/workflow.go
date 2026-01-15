package secretstest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	startTime := time.Now()
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
	absInputPaths := make([]string, len(inputPaths))
	for i, p := range inputPaths {
		absPath, absErr := filepath.Abs(p)
		if absErr != nil {
			logger.Error().Err(absErr).Msg("could not get absolute path for: " + p)
			return nil, cli_errors.NewGeneralSecretsFailureError("Unable to get absolute path")
		}
		absInputPaths[i] = filepath.Clean(absPath)
	}
	fmt.Println("INPUT PATH: ", inputPaths[0])

	workingDir := config.GetString(configuration.WORKING_DIRECTORY)
	if workingDir == "" {
		getwd, gerr := os.Getwd()
		if gerr != nil {
			logger.Error().Err(gerr).Msg("could not get current working directory")
			return nil, cli_errors.NewGeneralSecretsFailureError(UnableToInitializeError)
		}
		workingDir = getwd
	}

	rootFolder, repoURL, err := findCommonRoot(workingDir, absInputPaths)
	if err != nil {
		logger.Warn().Str("rootFolder", rootFolder).Str("repoURL", repoURL).Msg("could not determine common repo root: " + err.Error())
	}

	c, err := NewCommand(ictx, u, orgID, rootFolder, repoURL, NewWorkflowClients)
	if err != nil {
		logger.Error().Err(err).Msg("could not initialize command")
		return nil, cli_errors.NewGeneralSecretsFailureError(UnableToInitializeError)
	}

	logger.Info().Str("workingDir", workingDir).Strs("absInputPaths", absInputPaths).Str("repoURL", repoURL).Str("rootFolder", rootFolder).Msg("Running secrets workflow...")
	output, err := c.RunWorkflow(ctx, absInputPaths, workingDir)
	if err != nil {
		logger.Error().Err(err).Msg("workflow execution failed")
		return nil, cli_errors.NewGeneralSecretsFailureError("workflow execution failed")
	}

	duration := time.Since(startTime)
	logger.Info().Msg("duration: " + duration.String())
	return output, nil
}
