package upload

import (
	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type Client struct {
	fileupload.Client
}

func NewClient(ictx workflow.InvocationContext, orgID string) (*Client, error) {
	config := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	baseURL := config.GetString(configuration.API_URL)
	cfg := fileupload.Config{BaseURL: baseURL, OrgID: uuid.MustParse(orgID)}

	uploadClient := fileupload.NewClient(httpClient, cfg)
	return &Client{
		uploadClient,
	}, nil
}
