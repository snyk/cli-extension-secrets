//nolint:testpackage // set up mocks
package secretstest

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
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

// createMockInvocationCtx creates a mock invocation context with default values.
func createMockInvocationCtx(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine) *mocks.MockInvocationContext {
	t.Helper()

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.API_URL, "https://api.snyk.io")

	mockLogger := zerolog.Nop()
	icontext := mocks.NewMockInvocationContext(ctrl)
	icontext.EXPECT().Context().Return(t.Context()).AnyTimes()
	icontext.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	icontext.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()
	icontext.EXPECT().GetEngine().Return(engine).AnyTimes()
	icontext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("secrets.test")).AnyTimes()
	mockNetwork := mocks.NewMockNetworkAccess(ctrl)
	mockNetwork.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(mockNetwork).AnyTimes()

	mockUI := mocks.NewMockUserInterface(ctrl)
	mockPB := new(MockProgressBar)
	mockPB.On("SetTitle", mock.Anything).Return()
	mockPB.On("UpdateProgress", mock.Anything).Return(nil)
	mockPB.On("Clear").Return(nil)
	mockUI.EXPECT().NewProgressBar().Return(mockPB).AnyTimes()
	icontext.EXPECT().GetUserInterface().Return(mockUI).AnyTimes()

	return icontext
}
