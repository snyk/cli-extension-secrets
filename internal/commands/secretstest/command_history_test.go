package secretstest

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mockupload "github.com/snyk/cli-extension-secrets/internal/clients/upload/mocks"
	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-secrets/internal/instrumentation"

	mock_testshim "github.com/snyk/cli-extension-secrets/internal/clients/testshim/mocks"
)

// fakeInstrumentation records the calls relevant to the git history flow.
type fakeInstrumentation struct {
	uploadTimeCalls    int
	gitBundleTimeCalls int
	gitHistoryScans    int
	gitBundleSizes     []int64
}

func (f *fakeInstrumentation) RecordGitHistoryScan()              { f.gitHistoryScans++ }
func (f *fakeInstrumentation) RecordSizeFiltered(_ int)           {}
func (f *fakeInstrumentation) RecordAnalysisTimeMs(_ time.Time)   {}
func (f *fakeInstrumentation) RecordFileFilterTimeMs(_ time.Time) {}
func (f *fakeInstrumentation) RecordTime(_ string, _ time.Time)   {}
func (f *fakeInstrumentation) RecordFileUploadTimeMs(_ time.Time) { f.uploadTimeCalls++ }
func (f *fakeInstrumentation) RecordGitBundleTimeMs(_ time.Time)  { f.gitBundleTimeCalls++ }
func (f *fakeInstrumentation) RecordGitBundleSizeMB(size int64) {
	f.gitBundleSizes = append(f.gitBundleSizes, size)
}

func historyUploadClient(clients *WorkflowClients) *mockupload.MockClient {
	return clients.HistoryFileUpload.(*mockupload.MockClient)
}

func TestCommand_uploadBundlePath(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), bundleFileName)
	revisionID := uuid.New()
	skipReason := errors.New("too large")

	tests := []struct {
		name         string
		result       fileupload.UploadResult
		uploadErr    error
		wantRevision string
		wantErr      string
		wantRecorded bool
	}{
		{
			name:         "success",
			result:       fileupload.UploadResult{RevisionID: revisionID},
			wantRevision: revisionID.String(),
			wantRecorded: true,
		},
		{
			name:         "other skipped files are ignored",
			result:       fileupload.UploadResult{RevisionID: revisionID, SkippedFiles: []fileupload.SkippedFile{{Path: "other.txt", Reason: skipReason}}},
			wantRevision: revisionID.String(),
			wantRecorded: true,
		},
		{
			name:      "upload error",
			uploadErr: errors.New("boom"),
			wantErr:   "boom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			clients, _, cmd := setupTestCommand(t, ctrl)
			clients.HistoryFileUpload = mockupload.NewMockClient(ctrl)

			historyUploadClient(clients).EXPECT().
				CreateRevisionFromChan(gomock.Any(), gomock.Any(), filepath.Dir(bundlePath)).
				DoAndReturn(func(_ context.Context, paths <-chan string, _ string) (fileupload.UploadResult, error) {
					// the bundle must be the one and only path sent for upload
					var got []string
					for p := range paths {
						got = append(got, p)
					}
					assert.Equal(t, []string{bundlePath}, got)
					return tt.result, tt.uploadErr
				})

			inst := &fakeInstrumentation{}
			ctx := cmdctx.WithInstrumentation(t.Context(), inst)

			revision, err := cmd.uploadBundlePath(ctx, bundlePath)

			if tt.wantErr != "" {
				require.Error(t, err)
				catalogErr := requireCatalogError(t, err)
				require.Error(t, catalogErr.Cause)
				assert.Contains(t, catalogErr.Cause.Error(), tt.wantErr)
				assert.Empty(t, revision)
				assert.Zero(t, inst.uploadTimeCalls)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantRevision, revision)
			assert.Equal(t, 1, inst.uploadTimeCalls)
		})
	}
}

func TestCommand_uploadBundlePath_NoInstrumentation(t *testing.T) {
	ctrl := gomock.NewController(t)
	clients, _, cmd := setupTestCommand(t, ctrl)
	clients.HistoryFileUpload = mockupload.NewMockClient(ctrl)
	historyUploadClient(clients).EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, paths <-chan string, _ string) (fileupload.UploadResult, error) {
			for range paths { //nolint:revive // drain the channel
			}
			return fileupload.UploadResult{RevisionID: uuid.New()}, nil
		})

	_, err := cmd.uploadBundlePath(t.Context(), filepath.Join(t.TempDir(), bundleFileName))
	require.NoError(t, err)
}

func historyTestContext(t *testing.T, ctrl *gomock.Controller, inst instrumentation.Instrumentation) (context.Context, *mocks.MockInvocationContext) {
	t.Helper()

	cfg := configuration.NewWithOpts()
	cfg.Set(configuration.TEMP_DIR_PATH, t.TempDir())

	mockIctx := mocks.NewMockInvocationContext(ctrl)
	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()

	ctx := cmdctx.WithIctx(t.Context(), mockIctx)
	if inst != nil {
		ctx = cmdctx.WithInstrumentation(ctx, inst)
	}
	return ctx, mockIctx
}

func TestCommand_RunGitHistoryWorkflow_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	clients, mockUI, cmd := setupTestCommand(t, ctrl)
	clients.HistoryFileUpload = mockupload.NewMockClient(ctrl)
	cmd.GitRootDir = newTestRepo(t, 2)

	inst := &fakeInstrumentation{}
	ctx, mockIctx := historyTestContext(t, ctrl, inst)
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(&url.URL{})
	mockUI.EXPECT().SetTitle(gomock.Any()).AnyTimes()

	var uploadedBundle string
	var uploadedSize int64
	historyUploadClient(clients).EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, paths <-chan string, _ string) (fileupload.UploadResult, error) {
			for p := range paths {
				uploadedBundle = p
				info, err := os.Stat(p)
				require.NoError(t, err, "bundle must exist while it is uploaded")
				uploadedSize = info.Size()
			}
			return fileupload.UploadResult{RevisionID: uuid.New()}, nil
		})

	handle := gafclientmocks.NewMockTestHandle(ctrl)
	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)
	setupMockTestResultForPrepareOutput(mockTestResult)
	mockTestResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
	mockTestResult.EXPECT().Get(testapi.TestResultComponents).Return(&[]testapi.TestComponent{}).AnyTimes()
	clients.TestAPIShim.(*mock_testshim.MockClient).EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handle, nil)
	handle.EXPECT().Wait(gomock.Any())
	handle.EXPECT().Result().Return(mockTestResult)

	output, err := cmd.RunGitHistoryWorkflow(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, output)

	// metrics
	assert.Equal(t, 1, inst.gitHistoryScans)
	assert.Equal(t, 1, inst.gitBundleTimeCalls)
	assert.Equal(t, []int64{uploadedSize}, inst.gitBundleSizes)
	assert.Positive(t, uploadedSize)
	assert.Equal(t, 1, inst.uploadTimeCalls)

	// the temp dir holding the bundle is cleaned up afterwards
	assert.NoFileExists(t, uploadedBundle)
}

func TestCommand_RunGitHistoryWorkflow_BundleFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	clients, _, cmd := setupTestCommand(t, ctrl)
	clients.HistoryFileUpload = mockupload.NewMockClient(ctrl) // no upload expected
	cmd.GitRootDir = filepath.Join(t.TempDir(), "not-a-repo")

	inst := &fakeInstrumentation{}
	ctx, _ := historyTestContext(t, ctrl, inst)

	output, err := cmd.RunGitHistoryWorkflow(ctx)

	require.Error(t, err)
	requireCatalogError(t, err)
	assert.Nil(t, output)
	assert.Equal(t, 1, inst.gitHistoryScans)
	assert.Zero(t, inst.gitBundleTimeCalls)
	assert.Empty(t, inst.gitBundleSizes)
}

func TestCommand_RunGitHistoryWorkflow_UploadFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	clients, mockUI, cmd := setupTestCommand(t, ctrl)
	clients.HistoryFileUpload = mockupload.NewMockClient(ctrl)
	cmd.GitRootDir = newTestRepo(t, 1)
	mockUI.EXPECT().SetTitle(gomock.Any()).AnyTimes()

	inst := &fakeInstrumentation{}
	ctx, _ := historyTestContext(t, ctrl, inst)

	historyUploadClient(clients).EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, paths <-chan string, _ string) (fileupload.UploadResult, error) {
			for range paths { //nolint:revive // drain the channel
			}
			return fileupload.UploadResult{}, errors.New("upload failed")
		})

	output, err := cmd.RunGitHistoryWorkflow(ctx)

	require.Error(t, err)
	requireCatalogError(t, err)
	assert.Nil(t, output)
	// the bundle was created and measured even though the upload failed
	assert.Equal(t, 1, inst.gitBundleTimeCalls)
	assert.Len(t, inst.gitBundleSizes, 1)
	assert.Zero(t, inst.uploadTimeCalls)
}

func TestCommand_RunGitHistoryWorkflow_EmptyGitRootDir(t *testing.T) {
	ctrl := gomock.NewController(t)
	clients, _, cmd := setupTestCommand(t, ctrl)
	clients.HistoryFileUpload = mockupload.NewMockClient(ctrl) // no upload expected
	cmd.GitRootDir = ""

	inst := &fakeInstrumentation{}
	ctx, _ := historyTestContext(t, ctrl, inst)

	output, err := cmd.RunGitHistoryWorkflow(ctx)

	require.Error(t, err)
	requireCatalogError(t, err)
	assert.Nil(t, output)
	assert.Zero(t, inst.gitBundleTimeCalls)
	assert.Empty(t, inst.gitBundleSizes)
}

// When the only file sent for upload is skipped, GAF's large file client does not return a result with SkippedFiles:
// it returns the result together with ErrNoFilesProvided, because nothing was uploaded.
// The skip reason must still reach the user, and it must not be reported as "no supported files".
func TestCommand_uploadBundlePath_OnlyFileSkipped(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), bundleFileName)
	skipReason := errors.New("file exceeds the maximum size")

	ctrl := gomock.NewController(t)
	clients, _, cmd := setupTestCommand(t, ctrl)
	clients.HistoryFileUpload = mockupload.NewMockClient(ctrl)
	historyUploadClient(clients).EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, paths <-chan string, _ string) (fileupload.UploadResult, error) {
			for range paths { //nolint:revive // drain the channel
			}
			return fileupload.UploadResult{
				RevisionID:   uuid.New(),
				SkippedFiles: []fileupload.SkippedFile{{Path: bundleFileName, Reason: skipReason}},
			}, fileupload.ErrNoFilesProvided
		})

	inst := &fakeInstrumentation{}
	ctx := cmdctx.WithInstrumentation(t.Context(), inst)

	revision, err := cmd.uploadBundlePath(ctx, bundlePath)

	require.Error(t, err)
	assert.Empty(t, revision)
	assert.Zero(t, inst.uploadTimeCalls)

	catalogErr := requireCatalogError(t, err)
	assert.NotContains(t, catalogErr.Detail, "No supported files found",
		"a skipped git bundle must not be reported as missing supported files")
	require.Error(t, catalogErr.Cause)
	assert.ErrorIs(t, catalogErr.Cause, skipReason, "the skip reason must be kept in the error chain")
	assert.Contains(t, catalogErr.Cause.Error(), "git history bundle")
}

func TestCommand_uploadBundlePath_SkippedForSize(t *testing.T) {
	tests := []struct {
		name   string
		reason error
	}{
		{
			name:   "file size limit",
			reason: &fileupload.FileSizeLimitError{FilePath: bundleFileName, FileSize: 11_000_000_000, Limit: 10_000_000_000},
		},
		{
			name:   "chunk count limit",
			reason: &fileupload.ChunkCountLimitError{FilePath: bundleFileName, FileSize: 11_000_000_000, ChunkSize: 125_000, ChunkCount: 88_000, Limit: 1000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			clients, _, cmd := setupTestCommand(t, ctrl)
			clients.HistoryFileUpload = mockupload.NewMockClient(ctrl)
			historyUploadClient(clients).EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, paths <-chan string, _ string) (fileupload.UploadResult, error) {
					for range paths { //nolint:revive // drain the channel
					}
					return fileupload.UploadResult{
						SkippedFiles: []fileupload.SkippedFile{{Path: bundleFileName, Reason: tt.reason}},
					}, fileupload.ErrNoFilesProvided
				})

			_, err := cmd.uploadBundlePath(t.Context(), filepath.Join(t.TempDir(), bundleFileName))

			catalogErr := requireCatalogError(t, err)
			assert.Equal(t, "File too large", catalogErr.Title)
			assert.Contains(t, catalogErr.Detail, "git history of this repository is too large")
			assert.NotContains(t, catalogErr.Detail, "No supported files found")
			assert.ErrorIs(t, catalogErr.Cause, tt.reason)
		})
	}
}

func TestErrorFactory_NewHistoryBundleSkippedError(t *testing.T) {
	nop := zerolog.Nop()
	ef := NewErrorFactory(&nop)

	t.Run("nil reason is a generic upload failure naming the bundle", func(t *testing.T) {
		catalogErr := requireCatalogError(t, ef.NewHistoryBundleSkippedError(bundleFileName, nil))
		assert.NotEqual(t, "File too large", catalogErr.Title)
		require.Error(t, catalogErr.Cause)
		assert.Contains(t, catalogErr.Cause.Error(), bundleFileName)
	})

	t.Run("other reasons are a generic upload failure that keeps the reason", func(t *testing.T) {
		reason := errors.New("permission denied")
		catalogErr := requireCatalogError(t, ef.NewHistoryBundleSkippedError(bundleFileName, reason))
		assert.NotEqual(t, "File too large", catalogErr.Title)
		assert.ErrorIs(t, catalogErr.Cause, reason)
	})
}
