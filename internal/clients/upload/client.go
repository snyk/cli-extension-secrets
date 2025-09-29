package upload

import "github.com/snyk/go-application-framework/pkg/workflow"

type Client struct {
	// TODO: use the client provided by them (if any?)
	// or write one directly on top of the http client like
	// https://github.com/snyk/cli-extension-os-flows/blob/d279e5c83acaf21f3c6a2ba4849ffe8e274b577b/internal/bundlestore/client.go#L19-L31
}

func NewClient(_ workflow.InvocationContext) (*Client, error) {
	return &Client{}, nil
}
