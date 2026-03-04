package secretstest

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"

	mockupload "github.com/snyk/cli-extension-secrets/internal/clients/upload/mocks"
	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
	mock_secretstest "github.com/snyk/cli-extension-secrets/internal/commands/secretstest/testdata/mocks"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mock_testshim "github.com/snyk/cli-extension-secrets/internal/clients/testshim/mocks"
)

func TestCommand_RunWorkflow_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup test case
	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	mockUploadClient := mockClients.FileUpload.(*mockupload.MockClient)
	mockUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Return(fileupload.UploadResult{RevisionID: uuid.New()}, nil)

	// Mock successful scan trigger
	mockTestShimClient := mockClients.TestAPIShim.(*mock_testshim.MockClient)
	handle := gafclientmocks.NewMockTestHandle(ctrl)
	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)

	mockTestShimClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handle, nil)
	handle.EXPECT().Wait(gomock.Any())
	handle.EXPECT().Result().Return(mockTestResult)
	mockTestResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()

	findingContent, err := os.ReadFile("./testdata/finding.json")
	if err != nil {
		t.Fatalf("Error reading mock file: %v", err)
	}

	var expectedFindings []testapi.FindingData
	err = json.Unmarshal(findingContent, &expectedFindings)
	if err != nil {
		t.Fatal("Error unmarshalling JSON mock")
	}

	mockTestResult.EXPECT().Findings(gomock.Any()).Return(expectedFindings, true, nil).AnyTimes()

	// Mock successful test result prepare
	testID := uuid.New()
	mockTestResult.EXPECT().GetTestID().Return(&testID)
	mockTestResult.EXPECT().GetTestConfiguration().Return(&testapi.TestConfiguration{})
	mockTestResult.EXPECT().GetCreatedAt().Return(&time.Time{})
	mockTestResult.EXPECT().GetTestSubject().Return(&testapi.TestSubject{})
	mockTestResult.EXPECT().GetSubjectLocators().Return(&[]testapi.TestSubjectLocator{})
	mockTestResult.EXPECT().GetErrors().Return(&[]testapi.IoSnykApiCommonError{})
	mockTestResult.EXPECT().GetWarnings().Return(&[]testapi.IoSnykApiCommonError{})
	mockTestResult.EXPECT().GetPassFail().Return(nil)
	mockTestResult.EXPECT().GetOutcomeReason().Return(nil)
	mockTestResult.EXPECT().GetBreachedPolicies().Return(nil)
	mockTestResult.EXPECT().GetEffectiveSummary().Return(nil)
	mockTestResult.EXPECT().GetRawSummary().Return(nil)
	mockTestResult.EXPECT().GetTestFacts().Return(nil)
	mockTestResult.EXPECT().GetMetadata().Return(make(map[string]interface{}))

	// Mock CLIUserInterface calls
	mockUI.EXPECT().SetTitle(gomock.Any()).AnyTimes()

	// Mock ictx
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(&url.URL{})

	// Execute
	output, err := cmd.RunWorkflow(ctx, ".")

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, output)
	assert.Empty(t, output[0].GetErrorList())

	// Check findings
	tr := ufm.GetTestResultsFromWorkflowData(output[0])
	findings, _, err := tr[0].Findings(ctx)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Len(t, expectedFindings, 1)
	// checking key to check if the same finding is returned
	assert.Equal(t, findings[0].Attributes.Key, expectedFindings[0].Attributes.Key)
}

func TestCommand_RunWorkflow_ReportWithAllProjectAttributes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	cmd.ReportConfig = ReportConfig{
		Report:                     true,
		TargetName:                 "my-project",
		TargetReference:            "main",
		ProjectBusinessCriticality: "critical",
		ProjectEnvironment:         "frontend,backend",
		ProjectLifecycle:           "production,development",
		ProjectTags:                "team=security,priority=high",
	}

	run, ctx := setupSuccessfulRunWithParamCapture(t, ctrl, mockClients, mockUI)
	output, err := cmd.RunWorkflow(ctx, ".")

	require.NoError(t, err)
	assert.NotEmpty(t, output)

	cfg := run.capturedParams.TestConfig()
	require.NotNil(t, cfg)

	require.NotNil(t, cfg.PublishReport)
	assert.True(t, *cfg.PublishReport)

	require.NotNil(t, cfg.TargetName)
	assert.Equal(t, "my-project", *cfg.TargetName)

	require.NotNil(t, cfg.TargetReference)
	assert.Equal(t, "main", *cfg.TargetReference)

	require.NotNil(t, cfg.ProjectBusinessCriticality)
	assert.Equal(t, "critical", *cfg.ProjectBusinessCriticality)

	require.NotNil(t, cfg.ProjectEnvironment)
	assert.Equal(t, []string{"frontend", "backend"}, *cfg.ProjectEnvironment)

	require.NotNil(t, cfg.ProjectLifecycle)
	assert.Equal(t, []string{"production", "development"}, *cfg.ProjectLifecycle)

	require.NotNil(t, cfg.ProjectTags)
	assert.Equal(t, []string{"team=security", "priority=high"}, *cfg.ProjectTags)
}

func TestCommand_RunWorkflow_ReportWithoutOptionalAttributes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	cmd.ReportConfig = ReportConfig{Report: true}

	run, ctx := setupSuccessfulRunWithParamCapture(t, ctrl, mockClients, mockUI)
	output, err := cmd.RunWorkflow(ctx, ".")

	require.NoError(t, err)
	assert.NotEmpty(t, output)

	cfg := run.capturedParams.TestConfig()
	require.NotNil(t, cfg)

	require.NotNil(t, cfg.PublishReport)
	assert.True(t, *cfg.PublishReport)

	assert.Nil(t, cfg.TargetName)
	assert.Nil(t, cfg.TargetReference)
	assert.Nil(t, cfg.ProjectBusinessCriticality)
	assert.Nil(t, cfg.ProjectEnvironment)
	assert.Nil(t, cfg.ProjectLifecycle)
	assert.Nil(t, cfg.ProjectTags)
}

func TestCommand_RunWorkflow_NoReportOmitsPublishAndAttributes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)

	run, ctx := setupSuccessfulRunWithParamCapture(t, ctrl, mockClients, mockUI)
	output, err := cmd.RunWorkflow(ctx, ".")

	require.NoError(t, err)
	assert.NotEmpty(t, output)

	cfg := run.capturedParams.TestConfig()
	require.NotNil(t, cfg)

	assert.Nil(t, cfg.PublishReport)
	assert.Nil(t, cfg.TargetName)
	assert.Nil(t, cfg.TargetReference)
	assert.Nil(t, cfg.ProjectBusinessCriticality)
	assert.Nil(t, cfg.ProjectEnvironment)
	assert.Nil(t, cfg.ProjectLifecycle)
	assert.Nil(t, cfg.ProjectTags)
}

func TestCommand_RunWorkflow_SeverityThresholdSetsLocalPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	cmd.SeverityThreshold = "high"

	run, ctx := setupSuccessfulRunWithParamCapture(t, ctrl, mockClients, mockUI)
	output, err := cmd.RunWorkflow(ctx, ".")

	require.NoError(t, err)
	assert.NotEmpty(t, output)

	cfg := run.capturedParams.TestConfig()
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.LocalPolicy)
	require.NotNil(t, cfg.LocalPolicy.SeverityThreshold)
	assert.Equal(t, testapi.Severity("high"), *cfg.LocalPolicy.SeverityThreshold)
}

func TestCommand_RunWorkflow_NoSeverityThresholdOmitsLocalPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)

	run, ctx := setupSuccessfulRunWithParamCapture(t, ctrl, mockClients, mockUI)
	output, err := cmd.RunWorkflow(ctx, ".")

	require.NoError(t, err)
	assert.NotEmpty(t, output)

	cfg := run.capturedParams.TestConfig()
	require.NotNil(t, cfg)
	assert.Nil(t, cfg.LocalPolicy)
}

func TestCommand_RunWorkflow_AlwaysSetsSecretsScanConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)

	run, ctx := setupSuccessfulRunWithParamCapture(t, ctrl, mockClients, mockUI)
	output, err := cmd.RunWorkflow(ctx, ".")

	require.NoError(t, err)
	assert.NotEmpty(t, output)

	cfg := run.capturedParams.TestConfig()
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.ScanConfig)
	assert.NotNil(t, cfg.ScanConfig.Secrets)
}

func TestCommand_RunWorkflow_PassesCorrectOrgID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	expectedOrgID := cmd.OrgID

	run, ctx := setupSuccessfulRunWithParamCapture(t, ctrl, mockClients, mockUI)
	output, err := cmd.RunWorkflow(ctx, ".")

	require.NoError(t, err)
	assert.NotEmpty(t, output)
	assert.Equal(t, expectedOrgID, run.capturedParams.OrgID())
}

func TestCommand_RunWorkflow_ReportWithSeverityThresholdCombined(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	cmd.SeverityThreshold = "medium"
	cmd.ReportConfig = ReportConfig{
		Report:     true,
		TargetName: "combo-project",
	}

	run, ctx := setupSuccessfulRunWithParamCapture(t, ctrl, mockClients, mockUI)
	output, err := cmd.RunWorkflow(ctx, ".")

	require.NoError(t, err)
	assert.NotEmpty(t, output)

	cfg := run.capturedParams.TestConfig()
	require.NotNil(t, cfg)

	require.NotNil(t, cfg.LocalPolicy)
	assert.Equal(t, testapi.Severity("medium"), *cfg.LocalPolicy.SeverityThreshold)

	require.NotNil(t, cfg.PublishReport)
	assert.True(t, *cfg.PublishReport)

	require.NotNil(t, cfg.TargetName)
	assert.Equal(t, "combo-project", *cfg.TargetName)

	require.NotNil(t, cfg.ScanConfig)
	assert.NotNil(t, cfg.ScanConfig.Secrets)
}

func Test_buildTestConfiguration_NoReportNoThreshold(t *testing.T) {
	cfg := buildTestConfiguration(&ReportConfig{}, "")

	require.NotNil(t, cfg.ScanConfig)
	assert.NotNil(t, cfg.ScanConfig.Secrets)
	assert.Nil(t, cfg.LocalPolicy)
	assert.Nil(t, cfg.PublishReport)
}

func Test_buildTestConfiguration_ThresholdOnly(t *testing.T) {
	cfg := buildTestConfiguration(&ReportConfig{}, "critical")

	require.NotNil(t, cfg.LocalPolicy)
	require.NotNil(t, cfg.LocalPolicy.SeverityThreshold)
	assert.Equal(t, testapi.Severity("critical"), *cfg.LocalPolicy.SeverityThreshold)
	assert.Nil(t, cfg.PublishReport)
}

func Test_buildTestConfiguration_ReportSetsPublishReport(t *testing.T) {
	cfg := buildTestConfiguration(&ReportConfig{Report: true}, "")

	require.NotNil(t, cfg.PublishReport)
	assert.True(t, *cfg.PublishReport)
}

func Test_buildTestConfiguration_CommaSeparatedEnvironment(t *testing.T) {
	cfg := buildTestConfiguration(&ReportConfig{
		Report:             true,
		ProjectEnvironment: "frontend,backend,internal",
	}, "")

	require.NotNil(t, cfg.ProjectEnvironment)
	assert.Equal(t, []string{"frontend", "backend", "internal"}, *cfg.ProjectEnvironment)
}

func Test_buildTestConfiguration_CommaSeparatedLifecycle(t *testing.T) {
	cfg := buildTestConfiguration(&ReportConfig{
		Report:           true,
		ProjectLifecycle: "production,sandbox",
	}, "")

	require.NotNil(t, cfg.ProjectLifecycle)
	assert.Equal(t, []string{"production", "sandbox"}, *cfg.ProjectLifecycle)
}

func Test_buildTestConfiguration_CommaSeparatedTags(t *testing.T) {
	cfg := buildTestConfiguration(&ReportConfig{
		Report:      true,
		ProjectTags: "team=platform,priority=p1",
	}, "")

	require.NotNil(t, cfg.ProjectTags)
	assert.Equal(t, []string{"team=platform", "priority=p1"}, *cfg.ProjectTags)
}

func Test_buildTestConfiguration_AttributesIgnoredWhenReportFalse(t *testing.T) {
	cfg := buildTestConfiguration(&ReportConfig{
		Report:                     false,
		TargetName:                 "should-be-ignored",
		TargetReference:            "also-ignored",
		ProjectBusinessCriticality: "critical",
		ProjectEnvironment:         "frontend",
		ProjectLifecycle:           "production",
		ProjectTags:                "team=x",
	}, "")

	assert.Nil(t, cfg.PublishReport)
	assert.Nil(t, cfg.TargetName)
	assert.Nil(t, cfg.TargetReference)
	assert.Nil(t, cfg.ProjectBusinessCriticality)
	assert.Nil(t, cfg.ProjectEnvironment)
	assert.Nil(t, cfg.ProjectLifecycle)
	assert.Nil(t, cfg.ProjectTags)
}

func TestCommand_RunWorkflow_FailedFileUpload(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, _, cmd := setupTestCommand(t, ctrl)
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	mockUploadClient := mockClients.FileUpload.(*mockupload.MockClient)
	mockUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Return(fileupload.UploadResult{}, errors.New("upload failed"))

	_, err := cmd.RunWorkflow(ctx, ".")
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Cause.Error(), "upload failed")
}

func TestCommand_RunWorkflow_FailedTestTrigger(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	mockUploadClient := mockClients.FileUpload.(*mockupload.MockClient)
	mockUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Return(fileupload.UploadResult{RevisionID: uuid.New()}, nil)
	mockTestShimClient := mockClients.TestAPIShim.(*mock_testshim.MockClient)
	mockTestShimClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(nil, errors.New("start test failed"))

	mockUI.EXPECT().SetTitle(TitleScanning)

	_, err := cmd.RunWorkflow(ctx, ".")
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Cause.Error(), "start test failed")
}

func TestCommand_RunWorkflow_FailedTestTrigger_ErrOnWait(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	mockUploadClient := mockClients.FileUpload.(*mockupload.MockClient)
	handle := gafclientmocks.NewMockTestHandle(ctrl)

	mockUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Return(fileupload.UploadResult{RevisionID: uuid.New()}, nil)
	mockTestShimClient := mockClients.TestAPIShim.(*mock_testshim.MockClient)
	mockTestShimClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handle, nil)
	handle.EXPECT().Wait(gomock.Any()).Return(errors.New("wait failed"))

	mockUI.EXPECT().SetTitle(TitleScanning)

	_, err := cmd.RunWorkflow(ctx, ".")
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Cause.Error(), "wait failed")
}

func TestCommand_RunWorkflow_FailedTestTrigger_IncompleteFindings(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	mockUploadClient := mockClients.FileUpload.(*mockupload.MockClient)
	handle := gafclientmocks.NewMockTestHandle(ctrl)
	testResult := gafclientmocks.NewMockTestResult(ctrl)

	mockUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Return(fileupload.UploadResult{RevisionID: uuid.New()}, nil)
	mockTestShimClient := mockClients.TestAPIShim.(*mock_testshim.MockClient)
	mockTestShimClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handle, nil)
	handle.EXPECT().Wait(gomock.Any()).Return(nil)
	handle.EXPECT().Result().Return(testResult)
	testResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished)
	testResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, false, nil)

	mockUI.EXPECT().SetTitle(TitleScanning)

	_, err := cmd.RunWorkflow(ctx, ".")
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Cause.Error(), "test execution error: test completed but findings could not be retrieved")
}

func TestCommand_RunWorkflow_FailedTestTrigger_TestExecutionFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, mockUI, cmd := setupTestCommand(t, ctrl)
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	mockUploadClient := mockClients.FileUpload.(*mockupload.MockClient)
	handle := gafclientmocks.NewMockTestHandle(ctrl)
	testResult := gafclientmocks.NewMockTestResult(ctrl)

	mockUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Return(fileupload.UploadResult{RevisionID: uuid.New()}, nil)
	mockTestShimClient := mockClients.TestAPIShim.(*mock_testshim.MockClient)
	mockTestShimClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handle, nil)
	handle.EXPECT().Wait(gomock.Any()).Return(nil)
	handle.EXPECT().Result().Return(testResult)
	testResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesErrored)
	testResult.EXPECT().GetErrors().Return(&[]testapi.IoSnykApiCommonError{
		{
			Detail: "scanner error",
		},
	})

	mockUI.EXPECT().SetTitle(TitleScanning)

	_, err := cmd.RunWorkflow(ctx, ".")
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Cause.Error(), "scanner error")
}

func setupTestCommand(t *testing.T, ctrl *gomock.Controller) (*WorkflowClients, *mock_secretstest.MockUserInterface, *Command) {
	t.Helper()

	mockUploadClient := mockupload.NewMockClient(ctrl)
	mockTestShimClient := mock_testshim.NewMockClient(ctrl)
	mockUI := mock_secretstest.NewMockUserInterface(ctrl)

	mockClients := &WorkflowClients{
		FileUpload:  mockUploadClient,
		TestAPIShim: mockTestShimClient,
	}

	logger := zerolog.Nop()
	cmd := &Command{
		Logger:        &logger,
		OrgID:         uuid.New().String(),
		Clients:       mockClients,
		ErrorFactory:  NewErrorFactory(&logger),
		UserInterface: mockUI,
	}

	return mockClients, mockUI, cmd
}

type successfulRunResult struct {
	capturedParams testapi.StartTestParams
}

// setupSuccessfulRunWithParamCapture wires all mocks for a successful
// RunWorkflow, capturing the StartTestParams for post-run assertions.
func setupSuccessfulRunWithParamCapture(
	t *testing.T,
	ctrl *gomock.Controller,
	mockClients *WorkflowClients,
	mockUI *mock_secretstest.MockUserInterface,
) (*successfulRunResult, context.Context) {
	t.Helper()

	result := &successfulRunResult{}

	mockIctx := mocks.NewMockInvocationContext(ctrl)
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	mockUploadClient := mockClients.FileUpload.(*mockupload.MockClient)
	mockUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(fileupload.UploadResult{RevisionID: uuid.New()}, nil)

	mockTestShimClient := mockClients.TestAPIShim.(*mock_testshim.MockClient)
	handle := gafclientmocks.NewMockTestHandle(ctrl)
	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)

	mockTestShimClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
			result.capturedParams = params
			return handle, nil
		},
	)
	handle.EXPECT().Wait(gomock.Any())
	handle.EXPECT().Result().Return(mockTestResult)
	mockTestResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()

	findingContent, err := os.ReadFile("./testdata/finding.json")
	require.NoError(t, err)
	var expectedFindings []testapi.FindingData
	require.NoError(t, json.Unmarshal(findingContent, &expectedFindings))
	mockTestResult.EXPECT().Findings(gomock.Any()).Return(expectedFindings, true, nil).AnyTimes()

	testID := uuid.New()
	mockTestResult.EXPECT().GetTestID().Return(&testID)
	mockTestResult.EXPECT().GetTestConfiguration().Return(&testapi.TestConfiguration{})
	mockTestResult.EXPECT().GetCreatedAt().Return(&time.Time{})
	mockTestResult.EXPECT().GetTestSubject().Return(&testapi.TestSubject{})
	mockTestResult.EXPECT().GetSubjectLocators().Return(&[]testapi.TestSubjectLocator{})
	mockTestResult.EXPECT().GetErrors().Return(&[]testapi.IoSnykApiCommonError{})
	mockTestResult.EXPECT().GetWarnings().Return(&[]testapi.IoSnykApiCommonError{})
	mockTestResult.EXPECT().GetPassFail().Return(nil)
	mockTestResult.EXPECT().GetOutcomeReason().Return(nil)
	mockTestResult.EXPECT().GetBreachedPolicies().Return(nil)
	mockTestResult.EXPECT().GetEffectiveSummary().Return(nil)
	mockTestResult.EXPECT().GetRawSummary().Return(nil)
	mockTestResult.EXPECT().GetTestFacts().Return(nil)
	mockTestResult.EXPECT().GetMetadata().Return(make(map[string]interface{}))

	mockUI.EXPECT().SetTitle(gomock.Any()).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(&url.URL{})

	return result, ctx
}

// requireCatalogError ensures the error is a Snyk Catalog Error.
// It fails the test immediately if the error is nil or the wrong type.
func requireCatalogError(t *testing.T, err error) snyk_errors.Error {
	t.Helper()
	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	var catalogErr snyk_errors.Error
	if !errors.As(err, &catalogErr) {
		t.Fatalf("Expected a snyk_errors.Error, but got: %T (%v)", err, err)
	}
	return catalogErr
}
