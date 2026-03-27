// Package testshim provides a client for the Snyk test shim API.
package testshim

import (
	"context"
	"fmt"
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/snykclient"
)

// Client interface for the test shim API.
type Client interface {
	StartTest(ctx context.Context, params testapi.StartTestParams) (testapi.TestHandle, error)
}

// TestAPIClient wraps the test shim API client.
type TestAPIClient struct {
	testapi.TestClient
}

// NewClient creates a new TestAPIClient from the given invocation context.
func NewClient(ictx workflow.InvocationContext) (*TestAPIClient, error) {
	config := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	snykClient := snykclient.NewSnykClient(httpClient, config.GetString(configuration.API_URL), config.GetString(configuration.ORGANIZATION))

	testShimClient, err := testapi.NewTestClient(
		snykClient.GetAPIBaseURL(),
		testapi.WithPollInterval(2*time.Second),
		testapi.WithCustomHTTPClient(snykClient.GetClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create test API client: %w", err)
	}

	return &TestAPIClient{
		testShimClient,
	}, nil
}
