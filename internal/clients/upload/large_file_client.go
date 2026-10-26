package upload

import (
	"context"

	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// LargeFileClient defines the interface for uploading a single file that exceeds the per-file size limit.
type LargeFileClient interface {
	// TODO do we need the baseDir here
	CreateRevisionFromLargeFile(ctx context.Context, path string) (fileupload.LargeFileUploadResult, error)
}

// LargeFileUploadClient wraps the GAF large file upload client.
type LargeFileUploadClient struct {
	fileupload.LargeFileClient
}

// NewLargeFileClient creates a new LargeFileUploadClient for the given org.
func NewLargeFileClient(ictx workflow.InvocationContext, orgID string) (*LargeFileUploadClient, error) {
	config := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	baseURL := config.GetString(configuration.API_URL)
	cfg := fileupload.Config{BaseURL: baseURL, OrgID: uuid.MustParse(orgID)}

	return &LargeFileUploadClient{fileupload.NewLargeFileClient(httpClient, cfg)}, nil
}
