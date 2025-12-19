package upload

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type Client interface {
	CreateRevisionFromChan(ctx context.Context, paths <-chan string, baseDir string) (fileupload.UploadResult, error)
}

type FileUploadClient struct {
	fileupload.Client
}

func NewClient(ictx workflow.InvocationContext, orgID string) (*FileUploadClient, error) {
	org, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("unable to parse orgID: %s: %w", orgID, err)
	}

	config := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	baseURL := config.GetString(configuration.API_URL)
	cfg := fileupload.Config{BaseURL: baseURL, OrgID: org}

	uploadClient := fileupload.NewClient(httpClient, cfg, fileupload.WithLogger(ictx.GetEnhancedLogger()))
	return &FileUploadClient{uploadClient}, nil
}
