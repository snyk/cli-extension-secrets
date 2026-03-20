//nolint:testpackage // whitebox testing the workflow
package secretstest

import (
	"net/http"
	"path/filepath"
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

func TestSecretsWorkflow_JSONNotSupported(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagJSON, true)
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --json is not yet supported.")
}

func TestSecretsWorkflow_JSONFileOutputNotSupported(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagJSONFileOutput, "/tmp/output.json")
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --json is not yet supported.")
}

func TestSecretsWorkflow_SARIFNotSupported(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagSARIF, true)
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --sarif is not yet supported.")
}

func TestSecretsWorkflow_SARIFFileOutputNotSupported(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagSARIFFileOutput, "/tmp/output.sarif")
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --sarif is not yet supported.")
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

func TestSecretsWorkflow_NonGitRepo_ReportWithoutTargetName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tmpDir := t.TempDir()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.INPUT_DIRECTORY, []string{tmpDir})
	mockConfig.Set(FlagReport, true)

	mockIctx := setupMockIctxWithNetworkAccess(ctrl, mockConfig)

	_, _ = SecretsWorkflow(mockIctx, []workflow.Data{})

	assert.Equal(t, filepath.Base(tmpDir), mockConfig.GetString(FlagTargetName),
		"target-name should be set to dir name when the input is a non-git repo and scan is triggered with --report")
}

func TestSecretsWorkflow_NonGitRepo_ReportWithTargetName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tmpDir := t.TempDir()
	userTargetName := "my-custom-project-name"

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.INPUT_DIRECTORY, []string{tmpDir})
	mockConfig.Set(FlagReport, true)
	mockConfig.Set(FlagTargetName, userTargetName)

	mockIctx := setupMockIctxWithNetworkAccess(ctrl, mockConfig)

	_, _ = SecretsWorkflow(mockIctx, []workflow.Data{})

	assert.Equal(t, userTargetName, mockConfig.GetString(FlagTargetName),
		"user provided target-name should not be overwritten for --report on non-git repo input")
}

func TestSecretsWorkflow_NonGitRepo_WithoutReport(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tmpDir := t.TempDir()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.INPUT_DIRECTORY, []string{tmpDir})

	mockIctx := setupMockIctxWithNetworkAccess(ctrl, mockConfig)

	_, _ = SecretsWorkflow(mockIctx, []workflow.Data{})

	assert.Empty(t, mockConfig.GetString(FlagTargetName),
		"target-name should not be set for non-git repo input when --report is not used")
}

// setupMockIctx sets expectations on the mock invocation context when the workflow fails during the validation step.
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

// setupMockIctxWithNetworkAccess extends setupMockIctx with GetNetworkAccess expectations,
// needed when the workflow progresses past validation into client creation.
func setupMockIctxWithNetworkAccess(ctrl *gomock.Controller, mockConfig configuration.Configuration) *mocks.MockInvocationContext {
	logger := zerolog.Nop()
	mockIctx := mocks.NewMockInvocationContext(ctrl)
	mockUserInterface := mocks.NewMockUserInterface(ctrl)
	mockProgressBar := mocks.NewMockProgressBar(ctrl)
	mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
	analyticsProvider := analytics.New()

	mockIctx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetUserInterface().Return(mockUserInterface)
	mockIctx.EXPECT().GetAnalytics().Return(analyticsProvider).AnyTimes()
	mockIctx.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()

	mockNetworkAccess.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()

	mockUserInterface.EXPECT().NewProgressBar().Return(mockProgressBar)
	mockProgressBar.EXPECT().SetTitle(gomock.Any()).AnyTimes()
	mockProgressBar.EXPECT().UpdateProgress(gomock.Any()).AnyTimes()
	mockProgressBar.EXPECT().Clear()

	return mockIctx
}
