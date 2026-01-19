//nolint:testpackage // whitebox testing the workflow
package secretstest

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func TestSecretsWorkflow_FFIsFalse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, false)
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	assert.Error(t, err)
	//nolint:errorlint // we want to check the snyk_error detail.
	assert.Contains(t, err.(snyk_errors.Error).Detail, "User not allowed to run without feature flag.")
}

func TestSecretsWorkflow_UnsupportedFlag(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagReport, true)
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	assert.Error(t, err)
	//nolint:errorlint // we want to check the snyk_error detail.
	assert.Contains(t, err.(snyk_errors.Error).Detail, "Flag --report is not yet supported.")
}

func TestSecretsWorkflow_OrgNotProvided(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(configuration.ORGANIZATION, "")
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	assert.Error(t, err)
	//nolint:errorlint // we want to check the snyk_error detail.
	assert.Contains(t, err.(snyk_errors.Error).Detail, "No org provided.")
}

func TestSecretsWorkflow_TooManyInputPaths(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.INPUT_DIRECTORY, []string{".", "other path"})
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	assert.Error(t, err)
	//nolint:errorlint // we want to check the snyk_error detail.
	assert.Contains(t, err.(snyk_errors.Error).Detail, "Only one input path is accepted.")
}

func TestSecretsWorkflow_InvalidFlags(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(FlagSeverityThreshold, "invalid-value")
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	assert.Error(t, err)
	//nolint:errorlint // we want to check the snyk_error detail.
	assert.Contains(t, err.(snyk_errors.Error).Detail, "invalid-value")
}

func setupMockIctx(ctrl *gomock.Controller, mockConfig configuration.Configuration) *mocks.MockInvocationContext {
	logger := zerolog.Nop()
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	mockUserInterface := mocks.NewMockUserInterface(ctrl)
	mockProgressBar := mocks.NewMockProgressBar(ctrl)

	mockIctx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetUserInterface().Return(mockUserInterface)

	mockUserInterface.EXPECT().NewProgressBar().Return(mockProgressBar)
	mockProgressBar.EXPECT().SetTitle("Validating configuration...")
	mockProgressBar.EXPECT().UpdateProgress(ui.InfiniteProgress)
	mockProgressBar.EXPECT().Clear()

	return mockIctx
}
