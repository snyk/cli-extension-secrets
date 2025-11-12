package upload

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type Client struct {
	fileupload.Client
	// currently using https://github.com/snyk/go-application-framework/pull/460/files
}


func NewClient(ictx workflow.InvocationContext) (*Client, error) {
	config := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	baseURL := config.GetString(configuration.API_URL)
	fuConfig := fileupload.Config{BaseURL: baseURL}
	
	uploadClient := fileupload.NewClient(httpClient, fuConfig)
	
	// TODO proper error handling?
	if uploadClient == nil {
		return nil, fmt.Errorf("failed to create test API client: %w", nil)
	}

	return &Client{
		uploadClient,
	}, nil
}
