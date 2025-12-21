package secretstest

import (
	"context"
	"encoding/json"
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
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
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

// makeTestShimClient allows mocking the test shim client creation in tests.
var makeTestShimClient = testshim.NewClient

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
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	//errFactory := errors.NewErrorFactory(logger)
	progressBar := ictx.GetUserInterface().NewProgressBar()
	
	ctx = cmdctx.WithIctx(ctx, ictx)
	ctx = cmdctx.WithConfig(ctx, config)
	ctx = cmdctx.WithLogger(ctx, logger)
	ctx = cmdctx.WithProgressBar(ctx, progressBar)
	// ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	// ctx = cmdctx.WithInstrumentation(ctx, instrumentation.NewGAFInstrumentation(ictx.GetAnalytics()))

	progressBar.SetTitle("Validating configuration...")
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	progressBar.UpdateProgress(ui.InfiniteProgress)
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	defer progressBar.Clear()

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

	output, err := runWorkflow(ctx, clients, orgID,inputPaths, workingDir)
	
	if err != nil {
		logger.Error().Err(err).Msg("workflow execution failed")
		return nil, cli_errors.NewGeneralCLIFailureError("Workflow execution failed.")
	}
	
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	progressBar.Clear()

	return output, nil
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
	orgID string,
	inputPaths []string,
	workingDir string,
)  ([]workflow.Data, error) {
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	//instrumentation := cmdctx.Instrumentation(ctx)

	logger.Debug().Msg("running secrets test workflow...")
	progressBar.SetTitle("Uploading files...")

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
		return nil, fmt.Errorf("error creating revision: %w", err)
	}

	logger.Debug().Str("revisionID", uploadRevision.RevisionID.String()).Msg("Upload result")
	
	repoUrl := "https://github.com/snyk/ancatest"  // TODO
	rootFolderId := "."							   // TODO
	
	testResource, err := createTestResource(uploadRevision.RevisionID.String(), repoUrl, rootFolderId)
	if err != nil {
		return nil, err
	}

	param := testapi.StartTestParams{
		OrgID:       orgID,
		Resources:   &[]testapi.TestResourceCreateItem{testResource},
		LocalPolicy: nil,
		ScanConfig: &testapi.ScanConfiguration{Secrets: &testapi.SecretsScanConfiguration{}},
	}

	progressBar.SetTitle("Scanning...")

	// result and findings for later use
	testResult, err := executeTest(ctx, clients.TestAPIShim, param, logger)
	progressBar.Clear();
	if err != nil {
		return nil, fmt.Errorf("failed test execution: %w", err)
	}	
	
	logger.Debug().Msg("preparing output for secrets test workflow...")
	
	output, err := prepareOutput(ctx, testResult);
	if err != nil {
		return nil, fmt.Errorf("failed to prepare output: %w", err)
	}
	
	return output,err; 
}

//nolint:ireturn // Returns interface because implementation is private
func executeTest(ctx context.Context,
	testClient testapi.TestClient,
	testParam testapi.StartTestParams,
	logger *zerolog.Logger,
) (testapi.TestResult, error) {
	testHandle, err := testClient.StartTest(ctx, testParam)
	if err != nil {
		return nil, fmt.Errorf("failed to start test: %w", err)
	}

	if waitErr := testHandle.Wait(ctx); waitErr != nil {
		return nil, fmt.Errorf("test run failed: %w", waitErr)
	}

	finalResult := testHandle.Result()
	if finalResult == nil {
		return nil, fmt.Errorf("test completed but no result was returned")
	}

	if finalResult.GetExecutionState() == testapi.TestExecutionStatesErrored {
		apiErrors := finalResult.GetErrors()
		if apiErrors != nil && len(*apiErrors) > 0 {
			var errorMessages []string
			for _, apiError := range *apiErrors {
				errorMessages = append(errorMessages, apiError.Detail)
			}
			return nil, fmt.Errorf("test execution error: %v", strings.Join(errorMessages, "; "))
		}
		return nil, fmt.Errorf("test execution error: %v", "an unknown error occurred")
	}

	// Get findings for the test
	findingsData, complete, err := finalResult.Findings(ctx)
	
	if err != nil {
		logger.Error().Err(err).Msg("Error fetching findings")
		if !complete && len(findingsData) > 0 {
			logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved as an error occurred")
		}
		return finalResult, fmt.Errorf("test execution error: test completed but findings could not be retrieved: %w", err)
	}

	if !complete {
		if len(findingsData) > 0 {
			logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved; findings retrieval incomplete")
		}
		return finalResult, fmt.Errorf("test execution error: test completed but findings could not be retrieved")
	}


	d, err := json.Marshal(findingsData)
    if err != nil {
        fmt.Println("Error:", err)
        //return
    }

    // Convert []byte to string to print it
    
	logger.Warn().Msgf("----AICI %s", d);
	return finalResult, nil

}


func prepareOutput(
	ctx context.Context,
	testResult testapi.TestResult,
	) ([]workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)

	var outputData []workflow.Data

	


	// always output the test result
	testResultData := ufm.CreateWorkflowDataFromTestResults(
		ictx.GetWorkflowIdentifier(),
		 []testapi.TestResult{testResult})

	if testResultData != nil {
		outputData = append(outputData, testResultData)
	}

	return  outputData, nil
}

func createTestResource(revisionID, repoUrl, rootFolderId string) (testapi.TestResourceCreateItem, error) {
	uploadResource := testapi.UploadResource{
		ContentType:   testapi.UploadResourceContentTypeSource,
		FilePatterns:  []string{}, // TODO: add file patterns
		RevisionId:    revisionID,
		RepositoryUrl: &repoUrl,
		RootFolderId:  &rootFolderId,
		Type:          testapi.Upload,
	}

	var baseResourceVariant testapi.BaseResourceVariantCreateItem
	if err := baseResourceVariant.FromUploadResource(uploadResource); err != nil {
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to create base resource variant: %w", err)
	}

	baseResource := testapi.BaseResourceCreateItem{
		Resource: baseResourceVariant,
		Type:     testapi.BaseResourceCreateItemTypeBase,
	}

	var testResource testapi.TestResourceCreateItem
	if err := testResource.FromBaseResourceCreateItem(baseResource); err != nil {
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to create test resource: %w", err)
	}

	return testResource, nil
}
