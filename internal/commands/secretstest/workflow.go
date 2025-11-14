package secretstest

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

const (
	FeatureFlagIsSecretsEnabled = "internal_snyk_feature_flag_is_secrets_enabled" //nolint:gosec // config key
	FilterAndUploadFilesTimeout = 5 * time.Second
	// LogFieldCount is the logger key for number of findings.
	LogFieldCount = "count"
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
	uploadCtx, cancelFindFiles := context.WithTimeout(ctx, FilterAndUploadFilesTimeout)
	defer cancelFindFiles()

	textFilesFilter := ff.NewPipeline(
		ff.WithConcurrency(runtime.NumCPU()),
		ff.WithFilters(
			ff.FileSizeFilter(logger),
			ff.TextFileOnlyFilter(logger),
		),
	)
	pathsChan := textFilesFilter.Filter(uploadCtx, inputPaths, logger)

	uploadRevision, err := clients.FileUpload.CreateRevisionFromChan(uploadCtx, pathsChan, workingDir)
	if err != nil {
		return fmt.Errorf("error creating revision: %w", err)
	}

	logger.Debug().Str("revisionID", uploadRevision.RevisionID.String()).Msg("Upload result")
	
	uploadResource := testapi.UploadResource{
		ContentType:  testapi.UploadResourceContentTypeSource,
		FilePatterns: []string{},               // TODO: add file patterns
		RevisionId:   uploadRevision.RevisionID.String(),
		Type: testapi.Upload,
	}
	
	var baseResourceVariant testapi.BaseResourceVariantCreateItem
	if err := baseResourceVariant.FromUploadResource(uploadResource); err != nil {
		return fmt.Errorf("failed to create base resource variant: %w", err)
	}

	baseResource := testapi.BaseResourceCreateItem{
		Resource: baseResourceVariant,
		Type:     testapi.BaseResourceCreateItemTypeBase,
	}

	var testResource testapi.TestResourceCreateItem
	if err := testResource.FromBaseResourceCreateItem(baseResource); err != nil {
		return fmt.Errorf("failed to create test resource: %w", err)
	}

	param := testapi.StartTestParams{
		OrgID: orgID,
		Resources: []testapi.TestResourceCreateItem{testResource},
		LocalPolicy:   nil,  //TODO what do we need here ?
	}

	//result and findings for later use 
	_, _, err := executeTest(ctx, tc, param, logger);

	
	if err != nil {
		return fmt.Errorf("failed test execution: %w", err)
	}

	// TODO: map findings https://snyksec.atlassian.net/browse/PS-88

	// https://snyksec.atlassian.net/wiki/spaces/RD/pages/3242262614/Test+API+for+Risk+Score#Solution
	// TODO: handle the output (use the module provided by IDE/CLI team that works with data layer findings?)

	return nil
}


func executeTest(ctx context.Context, testClient testapi.TestClient, testParam testapi.StartTestParams, logger *zerolog.Logger) (testapi.TestResult, []testapi.FindingData, error) {
	testHandle, err := testClient.StartTest(ctx, testParam)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start test: %w", err)
	}

	if waitErr := testHandle.Wait(ctx); waitErr != nil {
		return nil, nil, fmt.Errorf("test run failed: %w", waitErr)
	}

	finalResult := testHandle.Result()
	if finalResult == nil {
		return nil, nil, fmt.Errorf("test completed but no result was returned")
	}

	if finalResult.GetExecutionState() == testapi.TestExecutionStatesErrored {
		apiErrors := finalResult.GetErrors()
		if apiErrors != nil && len(*apiErrors) > 0 {
			var errorMessages []string
			for _, apiError := range *apiErrors {
				errorMessages = append(errorMessages, apiError.Detail)
			}
			return nil, nil, fmt.Errorf("test execution error: %v", strings.Join(errorMessages, "; "))
		}
		return nil, nil, fmt.Errorf("test execution error: %v", "an unknown error occurred");
	}

	// Get findings for the test
	findingsData, complete, err := finalResult.Findings(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("Error fetching findings")
		if !complete && len(findingsData) > 0 {
			logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved as an error occurred")
		}
		return finalResult, findingsData, fmt.Errorf("test execution error: test completed but findings could not be retrieved: %w", err);
	}

	if !complete {
		if len(findingsData) > 0 {
			logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved; findings retrieval incomplete")
		}
		return finalResult, findingsData, fmt.Errorf("test execution error: test completed but findings could not be retrieved");
	}
	
	return finalResult, findingsData, nil
}
