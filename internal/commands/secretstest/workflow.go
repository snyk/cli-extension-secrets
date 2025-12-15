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
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

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
	err = runWorkflow(ctx, testShimClient, uploadClient, orgID, inputPaths, logger)

	if err != nil {
		logger.Error().Err(err).Msg("workflow execution failed")
		return nil, cli_errors.NewGeneralCLIFailureError("Workflow execution failed.")
	}

	return nil, nil
}

func checkSecretsEnabled(config configuration.Configuration) error {
	// TODO: remove this after we're moving away from CB
	// and add different checks for settings/entitlement (with different error as well)
	if !config.GetBool(FeatureFlagIsSecretsEnabled) {
		return cli_errors.NewFeatureUnderDevelopmentError("User not allowed to run without feature flag.")
	}

	return nil
}

//nolint:unparam // TODO: remove this after adding the implem
func runWorkflow(
	ctx context.Context,
	tc *testshim.Client,
	_ *upload.Client,
	orgID string,
	_ []string,
	logger *zerolog.Logger,
) error {
	logger.Debug().Msg("running secrets test workflow v2...")

	// TODO: create the revision via the upload client
	repoURL := "https://github.com/gitleaks/fake-leaks"
	uploadResource := testapi.UploadResource{
		ContentType:  testapi.UploadResourceContentTypeSource,
		FilePatterns: []string{},                                     // TODO
		RevisionId:   string("e1e870d1-93ef-4a35-b6c6-0d184fe8e5ec"), // TODO replace placeholder
		// RevisionId:   uploadRevision.RevisionID.String(),
		Type:          testapi.Upload,
		RepositoryUrl: &repoURL,
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
	secretsConfig := make(map[string]interface{})

	param := testapi.StartTestParams{
		OrgID:     orgID,
		Resources: &[]testapi.TestResourceCreateItem{testResource},
		ScanConfig: &testapi.ScanConfiguration{
			Secrets: &secretsConfig,
		},
	}

	paramJSON, _ := json.MarshalIndent(param, "", "  ")
	logger.Debug().Msgf("StartTest parameters: %s", string(paramJSON))

	//result and findings for later use
	results, findings, err := executeTest(ctx, tc, param, logger)
	if err != nil {
		return fmt.Errorf("failed test execution: %w", err)
	}

	serializableResult, err := ufm.NewSerializableTestResult(ctx, results)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create serializable test result")
		return fmt.Errorf("failed to create serializable test result: %w", err)
	}

	if err := writeJSON(serializableResult, "df-test-result.json"); err != nil {
		logger.Error().Err(err).Msg("failed to write test result")
		return fmt.Errorf("failed to write test result: %w", err)
	}

	if err := writeJSON(findings, "df-findings.json"); err != nil {
		logger.Error().Err(err).Msg("failed to write findings")
		return fmt.Errorf("failed to write findings: %w", err)
	}

	logger.Info().Msg("wrote test-result.json and findings.json")

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
		return nil, nil, fmt.Errorf("test execution error: %v", "an unknown error occurred")
	}

	findingsData, complete, err := finalResult.Findings(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("Error fetching findings")
		if !complete && len(findingsData) > 0 {
			logger.Warn().Int("count", len(findingsData)).Msg("Partial findings retrieved as an error occurred")
		}
		return finalResult, findingsData, fmt.Errorf("test execution error: test completed but findings could not be retrieved: %w", err)
	}

	if !complete {
		if len(findingsData) > 0 {
			logger.Warn().Int("count", len(findingsData)).Msg("Partial findings retrieved; findings retrieval incomplete")
		}
		return finalResult, findingsData, fmt.Errorf("test execution error: test completed but findings could not be retrieved")
	}

	return finalResult, findingsData, nil
}

// writeJSON writes data to a JSON file
func writeJSON(data interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to write JSON to %s: %w", filename, err)
	}

	return nil
}
