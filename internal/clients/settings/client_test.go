package settings_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-secrets/internal/clients/settings"
)

// errRoundTripper mimics the Snyk network-access middleware, which maps a
// non-2xx response to an error-catalog error and returns a nil response.
type errRoundTripper struct {
	err error
}

func (rt errRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, rt.err
}

func TestIsSecretsEnabled_True(t *testing.T) {
	const orgID = "org-123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/rest/orgs/"+orgID+"/settings/secrets", r.URL.Path)
		assert.Equal(t, settings.APIVersion, r.URL.Query().Get("version"))

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"attributes":{"secrets_enabled":true}}}`))
	}))
	defer srv.Close()

	client := settings.NewClient(srv.Client(), srv.URL, orgID)
	enabled, err := client.IsSecretsEnabled(context.Background())

	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestIsSecretsEnabled_False(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"attributes":{"secrets_enabled":false}}}`))
	}))
	defer srv.Close()

	client := settings.NewClient(srv.Client(), srv.URL, "org-123")
	enabled, err := client.IsSecretsEnabled(context.Background())

	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsSecretsEnabled_Forbidden_NotEnabled(t *testing.T) {
	// A 401/403 means the org lacks the enableSecrets entitlement; the feature is
	// simply not enabled rather than an error condition.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`forbidden`))
		}))

		client := settings.NewClient(srv.Client(), srv.URL, "org-123")
		enabled, err := client.IsSecretsEnabled(context.Background())
		srv.Close()

		require.NoError(t, err)
		assert.False(t, enabled)
	}
}

func TestIsSecretsEnabled_MiddlewareForbidden_NotEnabled(t *testing.T) {
	// The network-access middleware maps a 403 to an error-catalog error (here a
	// SNYK-0005-style error carrying StatusCode 403) and returns a nil response.
	// The client must treat this as "not enabled", not surface the catalog error.
	forbidden := snyk.NewUnauthorisedError("Forbidden")
	forbidden.StatusCode = http.StatusForbidden

	httpClient := &http.Client{Transport: errRoundTripper{err: forbidden}}
	client := settings.NewClient(httpClient, "https://api.snyk.io", "org-123")

	enabled, err := client.IsSecretsEnabled(context.Background())

	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsSecretsEnabled_MiddlewareServerError_Propagates(t *testing.T) {
	// A non-401/403 catalog error (e.g. a 500) must be propagated, not swallowed.
	serverErr := snyk.NewServerError("Internal server error.")
	serverErr.StatusCode = http.StatusInternalServerError

	httpClient := &http.Client{Transport: errRoundTripper{err: serverErr}}
	client := settings.NewClient(httpClient, "https://api.snyk.io", "org-123")

	_, err := client.IsSecretsEnabled(context.Background())

	require.Error(t, err)
}

func TestIsSecretsEnabled_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`boom`))
	}))
	defer srv.Close()

	client := settings.NewClient(srv.Client(), srv.URL, "org-123")
	enabled, err := client.IsSecretsEnabled(context.Background())

	require.Error(t, err)
	assert.False(t, enabled)
	assert.Contains(t, err.Error(), "500")
}

func TestIsSecretsEnabled_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	client := settings.NewClient(srv.Client(), srv.URL, "org-123")
	_, err := client.IsSecretsEnabled(context.Background())

	require.Error(t, err)
}

func TestIsSecretsEnabled_EmptyOrg(t *testing.T) {
	client := settings.NewClient(http.DefaultClient, "http://example.com", "")
	_, err := client.IsSecretsEnabled(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization ID is required")
}
