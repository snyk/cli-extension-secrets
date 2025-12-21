package secretstest

import (
	"context"
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

// MockTestClient implements testapi.TestClient.
type MockTestClient struct {
	mock.Mock
}

func (m *MockTestClient) StartTest(ctx context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(testapi.TestHandle), args.Error(1)
}

// MockTestHandle implements testapi.TestHandle.
type MockTestHandle struct {
	mock.Mock
}

func (m *MockTestHandle) Wait(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockTestHandle) Result() testapi.TestResult {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(testapi.TestResult)
}

func (m *MockTestHandle) Done() <-chan struct{} {
	args := m.Called()
	return args.Get(0).(<-chan struct{})
}

// MockTestResult implements testapi.TestResult.
type MockTestResult struct {
	mock.Mock
}

func (m *MockTestResult) GetTestID() *uuid.UUID {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*uuid.UUID)
}

func (m *MockTestResult) GetTestConfiguration() *testapi.TestConfiguration {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*testapi.TestConfiguration)
}

func (m *MockTestResult) GetCreatedAt() *time.Time {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*time.Time)
}

func (m *MockTestResult) GetTestResources() *[]testapi.TestResource {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*[]testapi.TestResource)
}

func (m *MockTestResult) GetSubjectLocators() *[]testapi.TestSubjectLocator {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*[]testapi.TestSubjectLocator)
}

func (m *MockTestResult) GetTestSubject() *testapi.TestSubject {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*testapi.TestSubject)
}

func (m *MockTestResult) GetExecutionState() testapi.TestExecutionStates {
	args := m.Called()
	return args.Get(0).(testapi.TestExecutionStates)
}

func (m *MockTestResult) GetErrors() *[]testapi.IoSnykApiCommonError {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	res := args.Get(0).([]testapi.IoSnykApiCommonError)
	return &res
}

func (m *MockTestResult) GetWarnings() *[]testapi.IoSnykApiCommonError {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	res := args.Get(0).([]testapi.IoSnykApiCommonError)
	return &res
}

func (m *MockTestResult) GetPassFail() *testapi.PassFail {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*testapi.PassFail)
}

func (m *MockTestResult) GetOutcomeReason() *testapi.TestOutcomeReason {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*testapi.TestOutcomeReason)
}

func (m *MockTestResult) GetBreachedPolicies() *testapi.PolicyRefSet {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*testapi.PolicyRefSet)
}

func (m *MockTestResult) GetEffectiveSummary() *testapi.FindingSummary {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*testapi.FindingSummary)
}

func (m *MockTestResult) GetRawSummary() *testapi.FindingSummary {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*testapi.FindingSummary)
}

func (m *MockTestResult) SetMetadata(key string, value interface{}) {
	m.Called(key, value)
}

func (m *MockTestResult) GetMetadata() map[string]interface{} {
	args := m.Called()
	return args.Get(0).(map[string]interface{})
}

func (m *MockTestResult) Findings(ctx context.Context) ([]testapi.FindingData, bool, error) {
	args := m.Called(ctx)
	return args.Get(0).([]testapi.FindingData), args.Bool(1), args.Error(2)
}

func (m *MockTestResult) GetTestFacts() *[]testapi.TestFact {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*[]testapi.TestFact)
}

// MockUploadClient implements upload.Client.
type MockUploadClient struct {
	mock.Mock
}

func (m *MockUploadClient) CreateRevisionFromChan(ctx context.Context, paths <-chan string, baseDir string) (fileupload.UploadResult, error) {
	args := m.Called(ctx, paths, baseDir)
	return args.Get(0).(fileupload.UploadResult), args.Error(1)
}

// MockProgressBar implements ui.ProgressBar.
type MockProgressBar struct {
	mock.Mock
}

func (m *MockProgressBar) SetTitle(title string) {
	m.Called(title)
}

func (m *MockProgressBar) UpdateProgress(progress float64) error {
	args := m.Called(progress)
	return args.Error(0)
}

func (m *MockProgressBar) Clear() error {
	args := m.Called()
	return args.Error(0)
}

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

	findingContent, err := os.ReadFile("mocks/finding.json")
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
	mockTestResult.On("GetTestResources").Return(&[]testapi.TestResource{})
	mockTestResult.On("GetSubjectLocators").Return(&[]testapi.TestSubjectLocator{})
	mockTestResult.On("GetErrors").Return(&[]testapi.IoSnykApiCommonError{})

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
