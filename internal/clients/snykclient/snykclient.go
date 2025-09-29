// Package snykclient provides a client for interacting with the Snyk API.
package snykclient

import (
	"net/http"
)

// Client is used for interacting with the Snyk API.
type Client struct {
	client     *http.Client
	apiBaseURL string
	orgID      string
}

// GetClient returns the HTTP client.
func (s *Client) GetClient() *http.Client {
	return s.client
}

// GetAPIBaseURL returns the API base URL.
func (s *Client) GetAPIBaseURL() string {
	// TODO: remove this when we go GA.
	return s.apiBaseURL + "/rest/"
}

// GetOrgID returns the organization ID.
func (s *Client) GetOrgID() string {
	return s.orgID
}

// NewSnykClient creates a new SnykClient instance.
func NewSnykClient(c *http.Client, apiBaseURL, orgID string) *Client {
	return &Client{
		client:     createNonRedirectingHTTPClient(c),
		apiBaseURL: apiBaseURL,
		orgID:      orgID,
	}
}

// createNonRedirectingHTTPClient creates a new HTTP client that doesn't follow redirects.
func createNonRedirectingHTTPClient(c *http.Client) *http.Client {
	newClient := http.Client{
		Transport: c.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &newClient
}
