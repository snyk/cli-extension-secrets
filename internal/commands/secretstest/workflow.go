package secretstest

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/rs/zerolog"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

// mockTestResultJSON has some mock test results coming from the test API
// TODO: remove this after done with testing
//
//go:embed testdata/mock_test_result.json
var mockTestResultJSON []byte

const (
	FeatureFlagIsSecretsEnabled = "feature_flag_is_secrets_enabled"
	FindSecretFilesTimeout      = 5 * time.Second
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
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	if err := checkSecretsEnabled(config); err != nil {
		return nil, err
	}

	// This will be removed after we enable the SCM Flows
	if config.IsSet(FlagReport) {
		return nil, cli_errors.NewFeatureUnderDevelopmentError("Flag --report is not yet supported.")
	}

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("no org provided")
		return nil, nil // TODO: error handling
	}

	err := validateFlagsConfig(config)
	if err != nil {
		return nil, err
	}

	// TODO: determine the input paths (default is .)
	// should we be able to scan multiple inputs?
	args := os.Args[1:]
	cwd, err := os.Getwd()
	if err != nil {
		logger.Error().Err(err).Msg("failed to read the current directory")
		return nil, cli_errors.NewGeneralCLIFailureError("Unable to get input.")
	}
	inputPaths := DetermineInputPaths(args, cwd)

	ignoreFiles := []string{".gitignore"}
	findFilesCtx, cancelFindFiles := context.WithTimeout(context.Background(), FindSecretFilesTimeout)
	defer cancelFindFiles()
	globFilteredFiles := ff.StreamAllowedFiles(findFilesCtx, inputPaths, ignoreFiles, ff.GetCustomGlobIgnoreRules(), logger)

	// Specialised filtering based on content and file metadata
	textFilesFilter := ff.NewPipeline(
		ff.WithConcurrency(runtime.NumCPU()),
		ff.WithFilters(
			ff.FileSizeFilter(logger),
			ff.TextFileOnlyFilter(logger),
		),
	)
	textFiles := textFilesFilter.Filter(globFilteredFiles)
	for file := range textFiles {
		logger.Debug().Msgf("Will upload '%s'", file)
	}

	// TODO: setup the clients
	// 1. for the upload api
	// 2. for the test-api-shim
	uploadClient, err := upload.NewClient(ictx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create upload client")
		return nil, cli_errors.NewGeneralCLIFailureError("Unable to initialize.")
	}
	testShimClient, err := testshim.NewClient(ictx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create test shim client")
		return nil, cli_errors.NewGeneralCLIFailureError("Unable to initialize.")
	}

	// TODO: here we need to pass all required clients (uploadapi, testshim)
	// better to create a wrapper struct with all the required clients
	ctx := context.Background()
	output, err := runWorkflow(ctx, testShimClient, uploadClient, inputPaths, logger)
	if err != nil {
		logger.Error().Err(err).Msg("workflow execution failed")
		return nil, cli_errors.NewGeneralCLIFailureError("Workflow execution failed.")
	}

	return output, nil
}

func checkSecretsEnabled(config configuration.Configuration) error {
	// TODO: remove this after we're moving away from CB
	// and add different checks for settings/entitlement (with different error as well)
	if !config.GetBool(FeatureFlagIsSecretsEnabled) {
		return cli_errors.NewFeatureUnderDevelopmentError("User not allowed to run without feature flag.")
	}

	return nil
}

func runWorkflow(
	ctx context.Context,
	_ *testshim.Client,
	_ *upload.Client,
	_ []string,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	logger.Debug().Msg("running secrets test workflow...")

	testResults, err := ufm.NewSerializableTestResultFromBytes(mockTestResultJSON)
	if err != nil {
		logger.Error().Err(err).Msg("failed to load embedded test result")
		return nil, fmt.Errorf("failed to load test result: %w", err)
	}

	if len(testResults) == 0 {
		logger.Warn().Msg("no test results loaded")
		return nil, nil
	}

	// we can only run one test
	testResult := testResults[0]

	logger.Debug().
		Str("testId", testResult.GetTestID().String()).
		Str("executionState", string(testResult.GetExecutionState())).
		Msg("loaded test result")

	findings, complete, err := testResult.Findings(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get findings from loaded result")
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}

	logger.Info().
		Int("findingsCount", len(findings)).
		Bool("complete", complete).
		Msg("findings loaded")

	output := ufm.CreateWorkflowDataFromTestResults(WorkflowID, testResults)
	return []workflow.Data{output}, nil
}
