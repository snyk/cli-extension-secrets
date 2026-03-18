//nolint:testpackage // whitebox testing the workflow
package secretstest

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
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
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "User not allowed to run without feature flag.")
}

func TestSecretsWorkflow_JSONDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagJSON, true)
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --json is temporarily disabled.")
}

func TestSecretsWorkflow_JSONFileOutputDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagJSONFileOutput, "/tmp/output.json")
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --json is temporarily disabled.")
}

func TestSecretsWorkflow_SARIFDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagSARIF, true)
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --sarif is temporarily disabled.")
}

func TestSecretsWorkflow_SARIFFileOutputDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagSARIFFileOutput, "/tmp/output.sarif")
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --sarif is temporarily disabled.")
}

func TestSecretsWorkflow_OrgNotProvided(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(configuration.ORGANIZATION, "")
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "No org provided.")
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
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Only one input path is accepted.")
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
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "invalid-value")
}

func setupMockIctx(ctrl *gomock.Controller, mockConfig configuration.Configuration) *mocks.MockInvocationContext {
	logger := zerolog.Nop()
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	mockUserInterface := mocks.NewMockUserInterface(ctrl)
	mockProgressBar := mocks.NewMockProgressBar(ctrl)
	analyticsProvider := analytics.New()

	mockIctx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetUserInterface().Return(mockUserInterface)
	mockIctx.EXPECT().GetAnalytics().Return(analyticsProvider).AnyTimes()

	mockUserInterface.EXPECT().NewProgressBar().Return(mockProgressBar)
	mockProgressBar.EXPECT().SetTitle("Validating configuration...")
	mockProgressBar.EXPECT().UpdateProgress(ui.InfiniteProgress)
	mockProgressBar.EXPECT().Clear()

	return mockIctx
}
