package snykclient_test

import (
	_ "embed"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-secrets/internal/clients/snykclient"
)

func TestNewSnykClient(t *testing.T) {
	client := snykclient.NewSnykClient(http.DefaultClient, "http://example.com", "org1")
	assert.NotNil(t, client)
}
