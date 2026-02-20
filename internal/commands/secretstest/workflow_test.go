//nolint:testpackage // whitebox testing the workflow
package secretstest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
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

func TestSecretsWorkflow_UnsupportedFlag(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockConfig := configuration.New()
	mockConfig.Set(FeatureFlagIsSecretsEnabled, true)
	mockConfig.Set(FlagReport, true)
	mockIctx := setupMockIctx(ctrl, mockConfig)

	_, err := SecretsWorkflow(mockIctx, []workflow.Data{})
	catalogErr := requireCatalogError(t, err)
	assert.Contains(t, catalogErr.Detail, "Flag --report is not yet supported.")
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

// TestQuotedPathWithTrailingSlash_BugDemo demonstrates that filepath.Abs
// alone does NOT strip stray quotes left by shell interpretation of
// "dir\" → dir". This test is expected to fail — it documents the bug.
func TestQuotedPathWithTrailingSlash_BugDemo(t *testing.T) {
	t.Skip("documents the bug; un-skip to verify it still reproduces")

	sep := string(filepath.Separator)
	path := strings.Join([]string{"a", "b", "c"}, sep)
	input := path + sep + `"`

	absPath, err := filepath.Abs(input)
	assert.NoError(t, err)
	assert.NotContains(t, absPath, `"`,
		"resolved path should not contain stray quote characters")
}

// TestNormalizeWorkflowInputPath_OsStatSucceeds exercises the real path
// the workflow takes: normalizeWorkflowInputPath → filepath.Abs → os.Stat.
// Without normalization, a stray quote makes os.Stat fail; with it, it works.
func TestNormalizeWorkflowInputPath_OsStatSucceeds(t *testing.T) {
	realDir := t.TempDir()
	sep := string(filepath.Separator)

	// Simulate the shell bug: "realDir\" → process receives realDir"
	poisoned := realDir + sep + `"`

	// Without the fix: filepath.Abs keeps the quote → os.Stat fails.
	absRaw, err := filepath.Abs(poisoned)
	assert.NoError(t, err)
	_, statErr := os.Stat(absRaw)
	assert.Error(t, statErr, "os.Stat should fail on a path containing a stray quote")

	// With the fix: normalize first → filepath.Abs → os.Stat succeeds.
	cleaned := normalizeWorkflowInputPath(poisoned)
	absCleaned, err := filepath.Abs(cleaned)
	assert.NoError(t, err)

	info, statErr := os.Stat(absCleaned)
	if assert.NoError(t, statErr, "os.Stat should succeed on the sanitized path") {
		assert.True(t, info.IsDir())
	}
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
