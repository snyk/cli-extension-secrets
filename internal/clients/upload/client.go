package upload

import (
	"context"

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
	config := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	baseURL := config.GetString(configuration.API_URL)
	cfg := fileupload.Config{BaseURL: baseURL, OrgID: uuid.MustParse(orgID)}

	uploadClient := fileupload.NewClient(httpClient, cfg)
	return &FileUploadClient{uploadClient}, nil
}
