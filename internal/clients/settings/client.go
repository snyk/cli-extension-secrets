// Package settings provides a client for reading org-level Secrets settings
// from the Snyk REST (v3) API.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/cli-extension-secrets/internal/clients/snykclient"
)

// APIVersion is the REST API version used when querying the Secrets settings
// endpoint.
const APIVersion = "2024-10-15"

// Client reads Secrets settings for an organization.
type Client interface {
	IsSecretsEnabled(ctx context.Context) (bool, error)
}

// secretsSettingsResponse models the JSON:API response of
// GET /rest/orgs/{org_id}/settings/secrets.
type secretsSettingsResponse struct {
	Data struct {
		Attributes struct {
			SecretsEnabled bool `json:"secrets_enabled"` //nolint:tagliatelle // REST API uses snake_case
		} `json:"attributes"`
	} `json:"data"`
}

// HTTPClient reads Secrets settings via the Snyk REST API. It wraps the shared
// snykclient, which provides the (non-redirecting) HTTP client, the REST base
// URL, and the org ID.
type HTTPClient struct {
	*snykclient.Client
}

// NewClient creates a Secrets settings client for the given org. The supplied
// http.Client is expected to be the Snyk network-access client so that auth and
// transport errors are mapped to error-catalog errors.
func NewClient(httpClient *http.Client, apiBaseURL, orgID string) *HTTPClient {
	return &HTTPClient{
		snykclient.NewSnykClient(httpClient, apiBaseURL, orgID),
	}
}

// IsSecretsEnabled reports whether the Secrets feature is enabled for the org,
// based on the data.attributes.secrets_enabled field returned by
// GET /rest/orgs/{org_id}/settings/secrets.
func (c *HTTPClient) IsSecretsEnabled(ctx context.Context) (bool, error) {
	orgID := c.GetOrgID()
	if orgID == "" {
		return false, fmt.Errorf("organization ID is required to read secrets settings")
	}

	endpoint, err := url.JoinPath(c.GetAPIBaseURL(), "orgs", orgID, "settings", "secrets")
	if err != nil {
		return false, fmt.Errorf("failed to build secrets settings URL: %w", err)
	}

	reqURL, err := url.Parse(endpoint)
	if err != nil {
		return false, fmt.Errorf("failed to parse secrets settings URL: %w", err)
	}
	query := reqURL.Query()
	query.Set("version", APIVersion)
	reqURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), http.NoBody)
	if err != nil {
		return false, fmt.Errorf("failed to create secrets settings request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := c.GetClient().Do(req)
	if err != nil {
		// The network-access client maps non-2xx responses to error-catalog errors
		// (and returns a nil response), so a 401/403 surfaces here rather than via
		// resp.StatusCode below. Treat it as "not enabled": the org lacks access or
		// the enableSecrets entitlement for this resource. Any other error (auth
		// before this point, network, 5xx) is propagated unchanged.
		if isNotEntitledError(err) {
			return false, nil
		}
		return false, err //nolint:wrapcheck // preserve error-catalog errors for the CLI
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return false, fmt.Errorf("failed to read secrets settings response: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			return false, nil
		}
		return false, fmt.Errorf("secrets settings endpoint returned status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed secretsSettingsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, fmt.Errorf("failed to parse secrets settings response: %w", err)
	}

	return parsed.Data.Attributes.SecretsEnabled, nil
}

// isNotEntitledError reports whether err is an error-catalog error carrying a
// 401 or 403 status, as produced by the network-access middleware for those
// responses. Such a status from the Secrets settings endpoint means the org
// lacks access/entitlement to the resource, i.e. the feature is not enabled.
func isNotEntitledError(err error) bool {
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) {
		return snykErr.StatusCode == http.StatusUnauthorized || snykErr.StatusCode == http.StatusForbidden
	}
	return false
}
