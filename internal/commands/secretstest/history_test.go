package secretstest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
	mockupload "github.com/snyk/cli-extension-secrets/internal/clients/upload/mocks"
	mock_secretstest "github.com/snyk/cli-extension-secrets/internal/commands/secretstest/testdata/mocks"
)

func setupHistory(t *testing.T, ctrl *gomock.Controller, bundlePath string) (*mockupload.MockLargeFileClient, *HistoryArgs) {
	t.Helper()

	logger := zerolog.Nop()
	ictx := mocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	ictx.EXPECT().GetWorkflowIdentifier().Return(WorkflowID).AnyTimes()

	ui := mock_secretstest.NewMockUserInterface(ctrl)
	ui.EXPECT().SetTitle(gomock.Any()).AnyTimes()

	client := mockupload.NewMockLargeFileClient(ctrl)
	return client, &HistoryArgs{
		InvocationContext: ictx,
		UserInterface:     ui,
		GetClient: func(workflow.InvocationContext, string) (upload.LargeFileClient, error) {
			return client, nil
		},
		ErrorFactory: NewErrorFactory(&logger),
		OrgID:        uuid.NewString(),
		BundlePath:   bundlePath,
	}
}

func TestHistoryWorkflow_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	bundle := filepath.Join(t.TempDir(), "repo.bundle")
	require.NoError(t, os.WriteFile(bundle, []byte("bundle"), 0o600))

	client, args := setupHistory(t, ctrl, bundle)
	revisionID := uuid.New()
	client.EXPECT().CreateRevisionFromLargeFile(gomock.Any(), bundle).
		Return(fileupload.LargeFileUploadResult{RevisionID: revisionID, Size: 6, ChunkCount: 1}, nil)

	output, err := HistoryWorkflow(t.Context(), args)

	require.NoError(t, err)
	require.Len(t, output, 1)
	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok)
	assert.Equal(t, revisionID.String()+"\n", string(payload))
}

func TestHistoryWorkflow_UploadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	bundle := filepath.Join(t.TempDir(), "repo.bundle")
	require.NoError(t, os.WriteFile(bundle, []byte("bundle"), 0o600))

	client, args := setupHistory(t, ctrl, bundle)
	client.EXPECT().CreateRevisionFromLargeFile(gomock.Any(), bundle).
		Return(fileupload.LargeFileUploadResult{}, errors.New("boom"))

	output, err := HistoryWorkflow(t.Context(), args)

	require.Error(t, err)
	assert.Nil(t, output)
}

func TestHistoryWorkflow_InvalidBundlePath(t *testing.T) {
	dir := t.TempDir()

	tests := map[string]string{
		"missing path": filepath.Join(dir, "missing.bundle"),
		"directory":    dir,
	}
	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			_, args := setupHistory(t, ctrl, path)

			output, err := HistoryWorkflow(t.Context(), args)

			require.Error(t, err)
			assert.Nil(t, output)
		})
	}
}
