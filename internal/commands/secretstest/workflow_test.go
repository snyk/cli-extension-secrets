//nolint:testpackage // whitebox testing the workflow
package secretstest

import (
	"errors"
	"net/http"
	"testing"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testShimMocks "github.com/snyk/cli-extension-secrets/internal/clients/testshim/mocks"
	uploadMocks "github.com/snyk/cli-extension-secrets/internal/clients/upload/mocks"
)

func TestSecretsWorkflow_FlagCombinations(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, ctrl *gomock.Controller, config configuration.Configuration, mockClients *WorkflowClients)
		wantErr error
	}{
		{
			name: "feature flag disabled, returns error",
			setup: func(t *testing.T, _ *gomock.Controller, config configuration.Configuration, _ *WorkflowClients) {
				t.Helper()
				config.Set(FeatureFlagIsSecretsEnabled, false)
			},
			wantErr: cli_errors.NewFeatureUnderDevelopmentError("User not allowed to run without feature flag."),
		},
		{
			name: "feature flag enabled, does not return error",
			setup: func(t *testing.T, _ *gomock.Controller, config configuration.Configuration, mockClients *WorkflowClients) {
				t.Helper()
				config.Set(FeatureFlagIsSecretsEnabled, true)
				tempDir := t.TempDir()
				config.Set(configuration.INPUT_DIRECTORY, tempDir)

				mockUploadClient, ok := mockClients.FileUpload.(*uploadMocks.MockClient)
				require.True(t, ok, "mock upload client is not of the expected type")

				mockUploadClient.EXPECT().
					CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(fileupload.UploadResult{}, nil)

				// TODO update this for test api shim
				// handler := testShimMocks.NewMockTestHandle(ctrl)
				// mockClients.TestAPIShim.(*testShimMocks.MockClient).EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handler, nil)
			},
			wantErr: nil,
		},
		{
			name: "file upload is failing",
			setup: func(t *testing.T, _ *gomock.Controller, config configuration.Configuration, mockClients *WorkflowClients) {
				t.Helper()
				config.Set(FeatureFlagIsSecretsEnabled, true)
				tempDir := t.TempDir()
				config.Set(configuration.INPUT_DIRECTORY, tempDir)

				mockUploadClient, ok := mockClients.FileUpload.(*uploadMocks.MockClient)
				require.True(t, ok, "mock upload client is not of the expected type")

				mockUploadClient.EXPECT().
					CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(fileupload.UploadResult{}, errors.New("no files provided"))

				// TODO update this for test api shim
				// handler := testShimMocks.NewMockTestHandle(ctrl)
				// mockClients.TestAPIShim.(*testShimMocks.MockClient).EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handler, nil)
			},
			wantErr: errors.New("no files provided"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClients := &WorkflowClients{
				FileUpload:  uploadMocks.NewMockClient(ctrl),
				TestAPIShim: testShimMocks.NewMockClient(ctrl),
			}

			// Replace the real client setup function with one that returns our mocks.
			originalSetupClientsFn := setupClientsFn
			setupClientsFn = func(_ workflow.InvocationContext, _ string, _ *zerolog.Logger) (*WorkflowClients, error) {
				return mockClients, nil
			}
			t.Cleanup(func() {
				setupClientsFn = originalSetupClientsFn
			})

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtx(t, ctrl, mockEngine)

			// Setup test case
			test.setup(t, ctrl, mockInvocationCtx.GetConfiguration(), mockClients)

			// Execute
			_, err := SecretsWorkflow(mockInvocationCtx, []workflow.Data{})

			// Verify
			if test.wantErr != nil {
				require.Error(t, err)
				assert.ErrorAs(t, err, &test.wantErr)
				assert.Equal(t, test.wantErr.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
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
	mockNetwork := mocks.NewMockNetworkAccess(ctrl)
	mockNetwork.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(mockNetwork).AnyTimes()

	return icontext
}
