// Package secretstest implements the Snyk secrets test workflow.
package secretstest

import (
	"context"
	"fmt"
	"path/filepath"
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

// Secrets workflow constants.
const (
	FilterAndUploadFilesTimeout = 30 * time.Second
	LogFieldCount               = "count"
)

// ReportConfig holds the configuration for the --report flag and related project attributes.
type ReportConfig struct {
	Report                     bool
	TargetName                 string
	TargetReference            string
	ProjectTags                string
	ProjectBusinessCriticality string
	ProjectEnvironment         string
	ProjectLifecycle           string
}

// CommandArgs holds the arguments required to construct a Command.
type CommandArgs struct {
	InvocationContext workflow.InvocationContext
	UserInterface     *CLIUserInterface
	GetClients        newClientsFunc
	OrgID             string
	RootFolderID      string
	RepoURL           string
	Branch            string
	CommitRef         string
	Excludes          []string
	ErrorFactory      *ErrorFactory
	SeverityThreshold string
	ReportConfig      ReportConfig
}

// Command orchestrates file upload, scanning, and output preparation for secrets testing.
type Command struct {
	Logger            *zerolog.Logger
	OrgID             string
	RootFolderID      string
	RepoURL           string
	Branch            string
	CommitRef         string
	Clients           *WorkflowClients
	Excludes          []string
	ErrorFactory      *ErrorFactory
	UserInterface     UserInterface
	SeverityThreshold string
	ReportConfig      ReportConfig
}

type newClientsFunc func(workflow.InvocationContext, string) (*WorkflowClients, error)

// WorkflowClients groups the API clients used during the secrets workflow.
type WorkflowClients struct {
	TestAPIShim testshim.Client
	FileUpload  upload.Client
}

// NewWorkflowClients creates the API clients needed for the secrets workflow.
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

// NewCommand constructs a Command from the provided arguments.
func NewCommand(args *CommandArgs) (*Command, error) {
	if args == nil {
		return nil, fmt.Errorf("args is nil")
	}
	if args.GetClients == nil {
		return nil, fmt.Errorf("GetClients function must be provided")
	}
	logger := args.InvocationContext.GetEnhancedLogger()

	clients, err := args.GetClients(args.InvocationContext, args.OrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to create clients: %w", err)
	}

	return &Command{
		Logger:            logger,
		Clients:           clients,
		OrgID:             args.OrgID,
		RepoURL:           args.RepoURL,
		Branch:            args.Branch,
		CommitRef:         args.CommitRef,
		RootFolderID:      args.RootFolderID,
		ErrorFactory:      args.ErrorFactory,
		UserInterface:     args.UserInterface,
		Excludes:          args.Excludes,
		SeverityThreshold: args.SeverityThreshold,
		ReportConfig:      args.ReportConfig,
	}, nil
}

// RunWorkflow uploads files, triggers a scan, and returns the formatted results.
func (c *Command) RunWorkflow(
	ctx context.Context,
	inputPath string,
) ([]workflow.Data, error) {
	c.Logger.Info().Msg("running secrets test workflow...")

	uploadRevision, err := c.filterAndUploadFiles(ctx, inputPath)
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
		return nil, c.ErrorFactory.NewPrepareOutputError(err)
	}

	return output, err
}

func (c *Command) filterAndUploadFiles(ctx context.Context, inputPath string) (string, error) {
	instrumentation := cmdctx.Instrumentation(ctx)

	textFilesFilter := ff.NewPipeline(
		ff.WithConcurrency(runtime.NumCPU()),
		ff.WithExcludeGlobs(c.Excludes),
		ff.WithFilters(
			ff.FileSizeFilter(c.Logger),
			ff.TextFileOnlyFilter(c.Logger),
		),
		ff.WithLogger(c.Logger),
		ff.WithAnalytics(instrumentation),
	)
	pathsChan := textFilesFilter.Filter(ctx, []string{inputPath})

	// for file inputPath we need to compute the relativity of the file path w.r.t. the file's dir
	dir := inputPath
	ok, err := isFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("failed to determine if inputPath is a file: %w", err)
	}
	if ok {
		dir = filepath.Dir(inputPath)
	}

	uploadStartTime := time.Now()
	uploadRevision, err := c.Clients.FileUpload.CreateRevisionFromChan(ctx, pathsChan, dir)
	if err != nil {
		return "", c.ErrorFactory.NewUploadError(err)
	}
	if instrumentation != nil {
		instrumentation.RecordFileUploadTimeMs(uploadStartTime)
	}

	c.Logger.Info().Msg(fmt.Sprintf("Revision ID: %s", uploadRevision.RevisionID))

	return uploadRevision.RevisionID.String(), nil
}

//nolint:ireturn // supposed to return interface.
func (c *Command) triggerScan(ctx context.Context, uploadRevision string) (testapi.TestResult, error) {
	instrumentation := cmdctx.Instrumentation(ctx)
	scanStartTime := time.Now()

	testResource, err := createTestResource(uploadRevision, c.RepoURL, c.RootFolderID, c.Branch, c.CommitRef)
	if err != nil {
		return nil, c.ErrorFactory.NewTestResourceError(err)
	}

	testConfig := buildTestConfiguration(&c.ReportConfig, c.SeverityThreshold)
	resources := []testapi.TestResourceCreateItem{testResource}
	param := testapi.NewStartTestParamsFromResources(c.OrgID, &resources, testConfig)

	testResult, err := c.executeTest(ctx, param)
	if err != nil {
		return nil, c.ErrorFactory.NewExecuteTestError(err)
	}

	if instrumentation != nil {
		instrumentation.RecordAnalysisTimeMs(scanStartTime)
	}
	return testResult, nil
}

func createTestResource(revisionID, repoURL, rootFolderID, branch, commitRef string) (testapi.TestResourceCreateItem, error) {
	uploadResource := testapi.UploadResource{
		ContentType:   testapi.UploadResourceContentTypeSource,
		FilePatterns:  []string{},
		RevisionId:    revisionID,
		RepositoryUrl: &repoURL,
		RootFolderId:  &rootFolderID,
		Type:          testapi.Upload,
	}

	uploadResource.ScmContext = buildScmContext(repoURL, branch, commitRef)

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

func buildScmContext(repoURL, branch, commitRef string) *testapi.ScmContext {
	if repoURL == "" && branch == "" && commitRef == "" {
		return nil
	}

	scmCtx := &testapi.ScmContext{}
	if repoURL != "" {
		scmCtx.RepoUrl = &repoURL
	}
	if branch != "" {
		scmCtx.Branch = &branch
	}
	if commitRef != "" {
		scmCtx.CommitRef = &commitRef
	}

	return scmCtx
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

func buildTestConfiguration(rc *ReportConfig, severityThreshold string) *testapi.TestConfiguration {
	cfg := &testapi.TestConfiguration{
		ScanConfig: &testapi.ScanConfiguration{Secrets: &testapi.SecretsScanConfiguration{}},
	}

	if severityThreshold != "" {
		threshold := testapi.Severity(severityThreshold)
		cfg.LocalPolicy = &testapi.LocalPolicy{
			SeverityThreshold: &threshold,
		}
	}

	if !rc.Report {
		return cfg
	}

	report := true
	cfg.PublishReport = &report

	if rc.TargetName != "" {
		cfg.TargetName = &rc.TargetName
	}
	if rc.TargetReference != "" {
		cfg.TargetReference = &rc.TargetReference
	}
	if rc.ProjectBusinessCriticality != "" {
		cfg.ProjectBusinessCriticality = &rc.ProjectBusinessCriticality
	}
	if rc.ProjectEnvironment != "" {
		envs := strings.Split(rc.ProjectEnvironment, ",")
		cfg.ProjectEnvironment = &envs
	}
	if rc.ProjectLifecycle != "" {
		lifecycles := strings.Split(rc.ProjectLifecycle, ",")
		cfg.ProjectLifecycle = &lifecycles
	}
	if rc.ProjectTags != "" {
		tags := strings.Split(rc.ProjectTags, ",")
		cfg.ProjectTags = &tags
	}

	return cfg
}
