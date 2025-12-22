//nolint:testpackage // whitebox testing the workflow
package secretstest

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testShimMocks "github.com/snyk/cli-extension-secrets/internal/clients/testshim/mocks"
	uploadMocks "github.com/snyk/cli-extension-secrets/internal/clients/upload/mocks"
	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
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
			setup: func(t *testing.T, ctrl *gomock.Controller, config configuration.Configuration, mockClients *WorkflowClients) {
				t.Helper()
				config.Set(FeatureFlagIsSecretsEnabled, true)
				tempDir := t.TempDir()
				config.Set(configuration.INPUT_DIRECTORY, tempDir)

				mockUploadClient, ok := mockClients.FileUpload.(*uploadMocks.MockClient)
				require.True(t, ok, "mock upload client is not of the expected type")

				mockUploadClient.EXPECT().
					CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(fileupload.UploadResult{}, nil)

				handler := testShimMocks.NewMockTestHandle(ctrl)
				mockClients.TestAPIShim.(*testShimMocks.MockClient).EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handler, nil)
				handler.EXPECT().Wait(gomock.Any()).Return(nil)

				mockResult := testShimMocks.NewMockTestResult(ctrl)
				handler.EXPECT().Result().Return(mockResult).AnyTimes()
				mockResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
				mockResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
				mockResult.EXPECT().GetTestID().Return(nil).AnyTimes()
				mockResult.EXPECT().GetTestConfiguration().Return(nil).AnyTimes()
				mockResult.EXPECT().GetCreatedAt().Return(nil).AnyTimes()
				mockResult.EXPECT().GetTestSubject().Return(nil).AnyTimes()
				mockResult.EXPECT().GetSubjectLocators().Return(nil).AnyTimes()
				mockResult.EXPECT().GetErrors().Return(nil).AnyTimes()
				mockResult.EXPECT().GetWarnings().Return(nil).AnyTimes()
				mockResult.EXPECT().GetPassFail().Return(nil).AnyTimes()
				mockResult.EXPECT().GetOutcomeReason().Return(nil).AnyTimes()
				mockResult.EXPECT().GetBreachedPolicies().Return(nil).AnyTimes()
				mockResult.EXPECT().GetEffectiveSummary().Return(nil).AnyTimes()
				mockResult.EXPECT().GetRawSummary().Return(nil).AnyTimes()
				mockResult.EXPECT().GetTestFacts().Return(nil).AnyTimes()
				mockResult.EXPECT().GetMetadata().Return(nil).AnyTimes()
			},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockProgressBar := new(MockProgressBar)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtx(t, ctrl, mockEngine)

			ctx := t.Context()
			logger := zerolog.Nop()
			ctx = cmdctx.WithLogger(ctx, &logger)
			ctx = cmdctx.WithProgressBar(ctx, mockProgressBar)
			ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
			mockInvocationCtx.EXPECT().Context().Return(ctx).AnyTimes()

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
