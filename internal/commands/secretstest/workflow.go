package secretstest

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/rs/zerolog"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

const (
	FeatureFlagIsSecretsEnabled = "internal_snyk_feature_flag_is_secrets_enabled" //nolint:gosec // config key
	FindSecretFilesTimeout      = 5 * time.Minute
)

var (
	WorkflowID     = workflow.NewWorkflowIdentifier("secrets.test")
	setupClientsFn = setupClients // internal for testing
)

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
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	if err := checkSecretsEnabled(config); err != nil {
		return nil, err
	}

	if config.IsSet(FlagReport) {
		return nil, cli_errors.NewFeatureUnderDevelopmentError("Flag --report is not yet supported.")
	}

	err := validateFlagsConfig(config)
	if err != nil {
		return nil, err
	}

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("no org provided")
		return nil, nil
	}

	inputPaths := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	logger.Info().Strs("inputPaths", inputPaths).Msg("the input paths")

	workingDir := config.GetString(configuration.WORKING_DIRECTORY)
	if workingDir == "" {
		getwd, gerr := os.Getwd()
		if gerr != nil {
			return nil, fmt.Errorf("could not get current working directory: %w", gerr)
		}
		workingDir = getwd
	}
	logger.Info().Str("workingDir", workingDir).Msg("the working dir")

	clients, err := setupClientsFn(ictx, orgID, logger)
	if err != nil {
		return nil, err
	}

	err = runWorkflow(ictx.Context(), clients, inputPaths, workingDir, logger)
	if err != nil {
		logger.Error().Err(err).Msg("workflow execution failed")
		return nil, cli_errors.NewGeneralCLIFailureError("Workflow execution failed.")
	}

	return nil, nil
}

func checkSecretsEnabled(config configuration.Configuration) error {
	if !config.GetBool(FeatureFlagIsSecretsEnabled) {
		return cli_errors.NewFeatureUnderDevelopmentError("User not allowed to run without feature flag.")
	}

	return nil
}

func setupClients(ictx workflow.InvocationContext, orgID string, logger *zerolog.Logger) (*WorkflowClients, error) {
	uploadClient, err := upload.NewClient(ictx, orgID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create upload client")
		return nil, cli_errors.NewGeneralCLIFailureError("Unable to initialize.")
	}
	testShimClient, err := testshim.NewClient(ictx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create test shim client")
		return nil, cli_errors.NewGeneralCLIFailureError("Unable to initialize.")
	}

	return &WorkflowClients{
		TestAPIShim: testShimClient,
		FileUpload:  uploadClient,
	}, nil
}

func runWorkflow(
	ctx context.Context,
	clients *WorkflowClients,
	inputPaths []string,
	workingDir string,
	logger *zerolog.Logger,
) error {
	logger.Debug().Msg("running secrets test workflow...")
	uploadCtx, cancelFindFiles := context.WithTimeout(ctx, FindSecretFilesTimeout)
	defer cancelFindFiles()

	textFilesFilter := ff.NewPipeline(
		ff.WithConcurrency(runtime.NumCPU()),
		ff.WithFilters(
			ff.FileSizeFilter(logger),
			ff.TextFileOnlyFilter(logger),
		),
	)
	pathsChan := textFilesFilter.Filter(uploadCtx, inputPaths, logger)

	uploadResult, err := clients.FileUpload.CreateRevisionFromChan(uploadCtx, pathsChan, workingDir)
	if err != nil {
		return fmt.Errorf("error creating revision: %w", err)
	}

	logger.Debug().Str("revisionID", uploadResult.RevisionID.String()).Msg("Upload result")

	return nil
}
