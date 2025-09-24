package testshim

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type Client struct {
	testapi.TestClient
}

func NewClient(ictx workflow.InvocationContext) (*Client, error) {
	config := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	baseURL := config.GetString(configuration.API_URL)

	// TODO: check again the http client configuration, see the config used in other places:
	// https://snyksec.atlassian.net/wiki/spaces/RD/pages/3242262614/Test+API+for+Risk+Score
	testShimClient, err := testapi.NewTestClient(
		baseURL,
		testapi.WithCustomHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create test API client: %w", err)
	}

	return &Client{
		testShimClient,
	}, nil
}
