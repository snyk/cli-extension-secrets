package secretstest

import (
	"github.com/snyk/cli-extension-secrets/internal/clients/testshim"
	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
)

type WorkflowClients struct {
	TestAPIShim      *testshim.Client
	FileUploadClient *upload.Client
}
