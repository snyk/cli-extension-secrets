package secretstest

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

const (
	FilterAndUploadFilesTimeout = 5 * time.Second
	LogFieldCount               = "count"
)

type Command struct {
	Logger        *zerolog.Logger
	OrgID         string
	RootFolderID  string
	RepoURL       string
	Clients       *WorkflowClients
	Excludes      []string
	ErrorFactory  *ErrorFactory
	UserInterface UserInterface
}

type newClientsFunc func(workflow.InvocationContext, string) (*WorkflowClients, error)

type WorkflowClients struct {
	TestAPIShim testshim.Client
	FileUpload  upload.Client
}

func NewWorkflowClients(ictx workflow.InvocationContext, orgID string) (*WorkflowClients, error) {
	uploadClient, err := upload.NewClient(ictx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to create upload client: %w", err)
	}

	testShimClient, err := testshim.NewClient(ictx)
	if err != nil {
		return nil, fmt.Errorf("failed to create test shim client: %w", err)
	}

	return &WorkflowClients{
		TestAPIShim: testShimClient,
		FileUpload:  uploadClient,
	}, nil
}

func NewCommand(ictx workflow.InvocationContext, u *CLIUserInterface, orgID, rootFolderID, repoURL string, getClients newClientsFunc) (*Command, error) {
	logger := ictx.GetEnhancedLogger()

	clients, err := getClients(ictx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to create clients: %w", err)
	}

	return &Command{
		Logger:        logger,
		Clients:       clients,
		OrgID:         orgID,
		RepoURL:       repoURL,
		RootFolderID:  rootFolderID,
		ErrorFactory:  NewErrorFactory(logger),
		UserInterface: u,
	}, nil
}

func (c *Command) RunWorkflow(
	ctx context.Context,
	inputPaths []string,
	workingDir string,
) ([]workflow.Data, error) {
	c.Logger.Info().Msg("running secrets test workflow...")

	uploadRevision, err := c.filterAndUploadFiles(ctx, inputPaths, workingDir)
	if err != nil {
		return nil, err
	}

	c.UserInterface.SetTitle(TitleScanning)
	testResult, err := c.triggerScan(ctx, uploadRevision)
	if err != nil {
		return nil, err
	}

	c.UserInterface.SetTitle(TitleRetrievingResults)
	output, err := prepareOutput(ctx, testResult)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare output: %w", err)
	}

	return output, err
}

func (c *Command) filterAndUploadFiles(ctx context.Context, inputPaths []string, wd string) (string, error) {
	uploadCtx, cancelFindFiles := context.WithTimeout(ctx, FilterAndUploadFilesTimeout)
	defer cancelFindFiles()

	textFilesFilter := ff.NewPipeline(
		ff.WithConcurrency(runtime.NumCPU()),
		ff.WithFilters(
			ff.FileSizeFilter(c.Logger),
			ff.TextFileOnlyFilter(c.Logger),
		),
		ff.WithLogger(c.Logger),
	)

	pathsChan := textFilesFilter.Filter(uploadCtx, inputPaths)
	uploadRevision, err := c.Clients.FileUpload.CreateRevisionFromChan(uploadCtx, pathsChan, wd)
	if err != nil {
		return "", c.ErrorFactory.CreateRevisionError(err)
	}
	c.Logger.Info().Msg(fmt.Sprintf("Revision ID: %s", uploadRevision.RevisionID))

	return uploadRevision.RevisionID.String(), nil
}

//nolint:ireturn // supposed to return interface.
func (c *Command) triggerScan(ctx context.Context, uploadRevision string) (testapi.TestResult, error) {
	testResource, err := createTestResource(uploadRevision, c.RepoURL, c.RootFolderID)
	if err != nil {
		return nil, c.ErrorFactory.CreateTestResourceError(err)
	}

	param := testapi.StartTestParams{
		OrgID:       c.OrgID,
		Resources:   &[]testapi.TestResourceCreateItem{testResource},
		LocalPolicy: nil,
		ScanConfig:  &testapi.ScanConfiguration{Secrets: &testapi.SecretsScanConfiguration{}},
	}

	testResult, err := c.executeTest(ctx, param)
	if err != nil {
		return nil, c.ErrorFactory.ExecuteTestError(err)
	}

	return testResult, nil
}

func createTestResource(revisionID, repoURL, rootFolderID string) (testapi.TestResourceCreateItem, error) {
	uploadResource := testapi.UploadResource{
		ContentType:   testapi.UploadResourceContentTypeSource,
		FilePatterns:  []string{},
		RevisionId:    revisionID,
		RepositoryUrl: &repoURL,
		RootFolderId:  &rootFolderID,
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

func prepareOutput(
	ctx context.Context,
	testResult testapi.TestResult,
) ([]workflow.Data, error) {
	var outputData []workflow.Data
	ictx := cmdctx.Ictx(ctx)

	if ictx == nil {
		return nil, fmt.Errorf("invocation context is nil")
	}
	testResultData := ufm.CreateWorkflowDataFromTestResults(
		ictx.GetWorkflowIdentifier(),
		[]testapi.TestResult{testResult})

	if testResultData != nil {
		outputData = append(outputData, testResultData)
	}

	return outputData, nil
}

//nolint:ireturn // supposed to return interface.
func (c *Command) executeTest(ctx context.Context, params testapi.StartTestParams) (testapi.TestResult, error) {
	testHandle, err := c.Clients.TestAPIShim.StartTest(ctx, params)
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

	findingsData, complete, err := finalResult.Findings(ctx)
	if err != nil {
		c.Logger.Error().Err(err).Msg("Error fetching findings")
		if !complete && len(findingsData) > 0 {
			c.Logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved as an error occurred")
		}
		return nil, fmt.Errorf("test execution error: test completed but findings could not be retrieved: %w", err)
	}

	if !complete {
		if len(findingsData) > 0 {
			c.Logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved; findings retrieval incomplete")
		}
		return nil, fmt.Errorf("test execution error: test completed but findings could not be retrieved")
	}

	return finalResult, nil
}
