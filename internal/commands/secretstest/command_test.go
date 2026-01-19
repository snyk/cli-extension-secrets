package secretstest

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

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

func TestCommand_RunWorkflow_FailedFileUpload(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClients, _, cmd := setupTestCommand(t, ctrl)
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	ctx := cmdctx.WithIctx(t.Context(), mockIctx)

	mockUploadClient := mockClients.FileUpload.(*mockupload.MockClient)
	mockUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Return(fileupload.UploadResult{}, errors.New("upload failed"))

	_, err := cmd.RunWorkflow(ctx, ".")
	assert.NotEmpty(t, err)
	assert.Contains(t, err.Error(), "upload failed")
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
	assert.NotEmpty(t, err)
	assert.Contains(t, err.Error(), "start test failed")
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
	assert.NotEmpty(t, err)
	assert.Contains(t, err.Error(), "wait failed")
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
	assert.NotEmpty(t, err)
	assert.Contains(t, err.Error(), "test execution error: test completed but findings could not be retrieved")
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
	assert.NotEmpty(t, err)
	assert.Contains(t, err.Error(), "scanner error")
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
