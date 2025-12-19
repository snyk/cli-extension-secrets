package secretstest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
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

func TestRunWorkflow_Success(t *testing.T) {
	mockTestClient := new(MockTestClient)
	mockTestHandle := new(MockTestHandle)
	mockTestResult := new(MockTestResult)

	// Setup expectations.
	mockTestClient.On("StartTest", mock.Anything, mock.Anything).Return(mockTestHandle, nil)
	mockTestHandle.On("Wait", mock.Anything).Return(nil)
	mockTestHandle.On("Result").Return(mockTestResult)
	mockTestResult.On("GetExecutionState").Return(testapi.TestExecutionStatesFinished)
	mockTestResult.On("Findings", mock.Anything).Return([]testapi.FindingData{}, true, nil)

	ctx := t.Context()
	tc := &testshim.Client{TestClient: mockTestClient}
	uc := &upload.Client{}
	logger := zerolog.Nop()

	_, err := runWorkflow(ctx, tc, uc, "org-id", []string{"."}, &logger)

	assert.NoError(t, err)
	mockTestClient.AssertExpectations(t)
	mockTestHandle.AssertExpectations(t)
	mockTestResult.AssertExpectations(t)
}

func TestRunWorkflow_StartTestError(t *testing.T) {
	mockTestClient := new(MockTestClient)

	// Setup expectations.
	mockTestClient.On("StartTest", mock.Anything, mock.Anything).Return(nil, errors.New("start error"))

	ctx := t.Context()
	tc := &testshim.Client{TestClient: mockTestClient}
	uc := &upload.Client{}
	logger := zerolog.Nop()

	err := runWorkflow(ctx, tc, uc, "org-id", []string{"."}, &logger)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "start error")
	mockTestClient.AssertExpectations(t)
}

func TestRunWorkflow_WaitError(t *testing.T) {
	mockTestClient := new(MockTestClient)
	mockTestHandle := new(MockTestHandle)

	// Setup expectations.
	mockTestClient.On("StartTest", mock.Anything, mock.Anything).Return(mockTestHandle, nil)
	mockTestHandle.On("Wait", mock.Anything).Return(errors.New("wait error"))

	ctx := t.Context()
	tc := &testshim.Client{TestClient: mockTestClient}
	uc := &upload.Client{}
	logger := zerolog.Nop()

	err := runWorkflow(ctx, tc, uc, "org-id", []string{"."}, &logger)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wait error")
	mockTestClient.AssertExpectations(t)
	mockTestHandle.AssertExpectations(t)
}

func TestRunWorkflow_ExecutionError(t *testing.T) {
	mockTestClient := new(MockTestClient)
	mockTestHandle := new(MockTestHandle)
	mockTestResult := new(MockTestResult)

	// Setup expectations.
	mockTestClient.On("StartTest", mock.Anything, mock.Anything).Return(mockTestHandle, nil)
	mockTestHandle.On("Wait", mock.Anything).Return(nil)
	mockTestHandle.On("Result").Return(mockTestResult)
	mockTestResult.On("GetExecutionState").Return(testapi.TestExecutionStatesErrored)

	apiErrors := []testapi.IoSnykApiCommonError{{Detail: "api error details"}}
	mockTestResult.On("GetErrors").Return(apiErrors)

	ctx := t.Context()
	tc := &testshim.Client{TestClient: mockTestClient}
	uc := &upload.Client{}
	logger := zerolog.Nop()

	err := runWorkflow(ctx, tc, uc, "org-id", []string{"."}, &logger)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test execution error")
	assert.Contains(t, err.Error(), "api error details")

	mockTestClient.AssertExpectations(t)
	mockTestHandle.AssertExpectations(t)
	mockTestResult.AssertExpectations(t)
}
