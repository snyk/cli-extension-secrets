package secrets_test

import (
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	secretstest "github.com/snyk/cli-extension-secrets/internal/commands/secretstest"
	"github.com/snyk/cli-extension-secrets/pkg/secrets"
)

func TestInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	err := e.Init()
	assert.NoError(t, err)

	err = secrets.Init(e)
	assert.NoError(t, err)

	assertWorkflowExists(t, e, secretstest.WorkflowID)
}

func assertWorkflowExists(t *testing.T, e workflow.Engine, id *url.URL) {
	t.Helper()

	wflw, ok := e.GetWorkflow(id)
	assert.True(t, ok)
	assert.NotNil(t, wflw)
}
