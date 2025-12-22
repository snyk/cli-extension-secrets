package secretstest

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/mocks"

	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
)

func TestRunWorkflow_Success(t *testing.T) {
	mockTestClient := new(MockTestClient)
	mockTestHandle := new(MockTestHandle)
	mockTestResult := new(MockTestResult)
	mockUploadClient := new(MockUploadClient)
	mockProgressBar := new(MockProgressBar)

	ctrl := gomock.NewController(t)

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(t, ctrl, mockEngine)

	// Setup expectations.
	uploadResult := fileupload.UploadResult{
		RevisionID: uuid.New(),
	}

	mockProgressBar.On("SetTitle", mock.Anything).Return()
	mockProgressBar.On("Clear").Return(nil)

	mockUploadClient.On("CreateRevisionFromChan", mock.Anything, mock.Anything, mock.Anything).Return(uploadResult, nil)

	testID := uuid.New()
	mockTestClient.On("StartTest", mock.Anything, mock.Anything).Return(mockTestHandle, nil)

	mockTestHandle.On("Wait", mock.Anything).Return(nil)
	mockTestHandle.On("Result").Return(mockTestResult)

	findingContent, err := os.ReadFile("../../clients/testshim/mocks/finding.json")
	if err != nil {
		t.Fatalf("Error reading mock file: %v", err)
	}

	var findings []testapi.FindingData

	err = json.Unmarshal(findingContent, &findings)
	if err != nil {
		t.Fatal("Error unmarshalling JSON mock")
	}

	mockTestResult.On("GetTestID").Return(&testID)
	mockTestResult.On("GetTestConfiguration").Return(&testapi.TestConfiguration{})
	mockTestResult.On("GetExecutionState").Return(testapi.TestExecutionStatesFinished)
	mockTestResult.On("Findings", mock.Anything).Return(findings, true, nil)
	mockTestResult.On("GetCreatedAt").Return(&time.Time{})
	mockTestResult.On("GetTestSubject").Return(&testapi.TestSubject{})
	mockTestResult.On("GetSubjectLocators").Return(&[]testapi.TestSubjectLocator{})
	mockTestResult.On("GetErrors").Return([]testapi.IoSnykApiCommonError{})
	mockTestResult.On("GetWarnings").Return([]testapi.IoSnykApiCommonError{})
	mockTestResult.On("GetPassFail").Return(nil)
	mockTestResult.On("GetOutcomeReason").Return(nil)
	mockTestResult.On("GetBreachedPolicies").Return(nil)
	mockTestResult.On("GetEffectiveSummary").Return(nil)
	mockTestResult.On("GetRawSummary").Return(nil)
	mockTestResult.On("GetTestFacts").Return(nil)
	mockTestResult.On("GetMetadata").Return(make(map[string]interface{}))

	ctx := t.Context()
	logger := zerolog.Nop()
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithProgressBar(ctx, mockProgressBar)
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)

	clients := &WorkflowClients{
		TestAPIShim: mockTestClient,
		FileUpload:  mockUploadClient,
	}

	_, err = runWorkflow(ctx, clients, "org-id", []string{"."}, ".")

	assert.NoError(t, err)
	mockTestClient.AssertExpectations(t)
	mockTestHandle.AssertExpectations(t)
	mockTestResult.AssertExpectations(t)
}

func TestRunWorkflow_StartTestError(t *testing.T) {
	mockTestClient := new(MockTestClient)
	mockUploadClient := new(MockUploadClient)
	mockProgressBar := new(MockProgressBar)

	ctrl := gomock.NewController(t)

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(t, ctrl, mockEngine)

	// Setup expectations.
	uploadResult := fileupload.UploadResult{
		RevisionID: uuid.New(),
	}

	mockProgressBar.On("SetTitle", mock.Anything).Return()
	mockProgressBar.On("Clear").Return(nil)

	mockUploadClient.On("CreateRevisionFromChan", mock.Anything, mock.Anything, mock.Anything).Return(uploadResult, nil)
	mockTestClient.On("StartTest", mock.Anything, mock.Anything).Return(nil, errors.New("start error"))

	ctx := t.Context()

	logger := zerolog.Nop()
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithProgressBar(ctx, mockProgressBar)
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)

	clients := &WorkflowClients{
		TestAPIShim: mockTestClient,
		FileUpload:  mockUploadClient,
	}

	_, err := runWorkflow(ctx, clients, "org-id", []string{"."}, ".")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "start error")
	mockTestClient.AssertExpectations(t)
}

func TestRunWorkflow_WaitError(t *testing.T) {
	mockTestClient := new(MockTestClient)
	mockTestHandle := new(MockTestHandle)
	mockUploadClient := new(MockUploadClient)
	mockProgressBar := new(MockProgressBar)

	ctrl := gomock.NewController(t)

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(t, ctrl, mockEngine)
	uploadResult := fileupload.UploadResult{
		RevisionID: uuid.New(),
	}

	// Setup expectations.
	mockUploadClient.On("CreateRevisionFromChan", mock.Anything, mock.Anything, mock.Anything).Return(uploadResult, nil)
	mockProgressBar.On("SetTitle", mock.Anything).Return()
	mockProgressBar.On("Clear").Return(nil)
	mockTestClient.On("StartTest", mock.Anything, mock.Anything).Return(mockTestHandle, nil)
	mockTestHandle.On("Wait", mock.Anything).Return(errors.New("wait error"))

	ctx := t.Context()
	logger := zerolog.Nop()
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithProgressBar(ctx, mockProgressBar)
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)

	clients := &WorkflowClients{
		TestAPIShim: mockTestClient,
		FileUpload:  mockUploadClient,
	}

	_, err := runWorkflow(ctx, clients, "org-id", []string{"."}, ".")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wait error")
	mockTestClient.AssertExpectations(t)
	mockTestHandle.AssertExpectations(t)
}

func TestRunWorkflow_ExecutionError(t *testing.T) {
	mockTestClient := new(MockTestClient)
	mockTestHandle := new(MockTestHandle)
	mockTestResult := new(MockTestResult)
	mockUploadClient := new(MockUploadClient)
	mockProgressBar := new(MockProgressBar)

	ctrl := gomock.NewController(t)

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(t, ctrl, mockEngine)

	uploadResult := fileupload.UploadResult{
		RevisionID: uuid.New(),
	}

	// Setup expectations.
	mockUploadClient.On("CreateRevisionFromChan", mock.Anything, mock.Anything, mock.Anything).Return(uploadResult, nil)

	mockProgressBar.On("SetTitle", mock.Anything).Return()
	mockProgressBar.On("Clear").Return(nil)
	mockTestClient.On("StartTest", mock.Anything, mock.Anything).Return(mockTestHandle, nil)
	mockTestHandle.On("Wait", mock.Anything).Return(nil)
	mockTestHandle.On("Result").Return(mockTestResult)
	mockTestResult.On("GetExecutionState").Return(testapi.TestExecutionStatesErrored)

	apiErrors := []testapi.IoSnykApiCommonError{{Detail: "api error details"}}
	mockTestResult.On("GetErrors").Return(apiErrors)

	ctx := t.Context()

	logger := zerolog.Nop()
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithProgressBar(ctx, mockProgressBar)
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)

	clients := &WorkflowClients{
		TestAPIShim: mockTestClient,
		FileUpload:  mockUploadClient,
	}

	_, err := runWorkflow(ctx, clients, "org-id", []string{"."}, ".")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test execution error")
	assert.Contains(t, err.Error(), "api error details")

	mockTestClient.AssertExpectations(t)
	mockTestHandle.AssertExpectations(t)
	mockTestResult.AssertExpectations(t)
}
