package secretstest_test

import (
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-secrets/internal/commands/secretstest"
)

func TestSecretsWorkflow_FlagCombinations(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(config configuration.Configuration, mockEngine *mocks.MockEngine)
		wantErr error
	}{
		{
			name: "feature flag disabled, returns error",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(secretstest.FeatureFlagIsSecretsEnabled, false)
			},
			wantErr: cli_errors.NewFeatureUnderDevelopmentError("User not allowed to run without feature flag."),
		},
		{
			name: "feature flag enabled, does not return error",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(secretstest.FeatureFlagIsSecretsEnabled, true)
			},
			wantErr: nil, // TODO: we'll need to use mocks for the clients for the happy path
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtx(t, ctrl, mockEngine)

			// Setup test case
			test.setup(mockInvocationCtx.GetConfiguration(), mockEngine)

			// Execute
			_, err := secretstest.SecretsWorkflow(mockInvocationCtx, []workflow.Data{})

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
func createMockInvocationCtx(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine) workflow.InvocationContext {
	t.Helper()

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.API_URL, "https://api.snyk.io")

	mockLogger := zerolog.Nop()

	icontext := mocks.NewMockInvocationContext(ctrl)
	icontext.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	icontext.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()
	icontext.EXPECT().GetEngine().Return(engine).AnyTimes()
	mockNetwork := mocks.NewMockNetworkAccess(ctrl)
	mockNetwork.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(mockNetwork).AnyTimes()

	return icontext
}
