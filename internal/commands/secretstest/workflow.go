package secretstest

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-secrets/internal/instrumentation"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Workflow configuration keys.
const (
	FeatureFlagIsSecretsEnabled = "internal_snyk_feature_flag_is_secrets_enabled" //nolint:gosec // config key
	InputPathKey                = "inputPath"
)

// WorkflowID is the unique identifier for the secrets test workflow.
var WorkflowID = workflow.NewWorkflowIdentifier("secrets.test")

// RegisterWorkflows registers the secrets test workflow and its feature flag with the engine.
func RegisterWorkflows(e workflow.Engine) error {
	flagSet := GetSecretsTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(flagSet)

	if _, err := e.Register(WorkflowID, c, SecretsWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}

	config_utils.AddFeatureFlagToConfig(e, FeatureFlagIsSecretsEnabled, "isSecretsEnabled")

	return nil
}

// SecretsWorkflow is the entry point for the secrets test workflow.
func SecretsWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	ctx := context.Background()
	ctx = cmdctx.WithIctx(ctx, ictx)
	ctx = cmdctx.WithInstrumentation(ctx, instrumentation.NewGAFInstrumentation(ictx.GetAnalytics()))

	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errorFactory := NewErrorFactory(logger)

	u := NewUI(ictx)
	u.SetTitle(TitleValidating)
	defer u.Clear()

	// validate config and prepare input path
	orgID, inputPath, err := validateAndPrepareInput(config, errorFactory)
	if err != nil {
		return nil, err
	}

	// identify git root and get repo data if available
	gitRootDir, err := findGitRoot(inputPath)
	if err != nil {
		// if the git root dir is not found it means the dir is not a git repo
		// in case of --report and no target name already set, we need to manually set the target name to the name of the dir
		// in order to enable target + project creation
		if config.IsSet(FlagReport) && !config.IsSet(FlagTargetName) {
			config.Set(FlagTargetName, filepath.Base(inputPath))
		}

		logger.Err(err).Str(InputPathKey, inputPath).Msg("could not determine common git root")
	}

	remoteRepoURLFlag := config.GetString(FlagRemoteRepoURL)
	repoContext := resolveGitContext(inputPath, gitRootDir, remoteRepoURLFlag, logger)

	// parse excludes
	excludeGlobs, err := parseExcludeFlag(config)
	if err != nil {
		return nil, errorFactory.NewInvalidFlagError(err)
	}

	// parse --report config
	reportConfig := buildReportConfig(config)

	args := &CommandArgs{
		InvocationContext: ictx,
		UserInterface:     u,
		OrgID:             orgID,
		RootFolderID:      repoContext.inputPathRelativeToGitRoot,
		RepoURL:           repoContext.repoURL,
		Branch:            repoContext.branch,
		CommitRef:         repoContext.commitRef,
		GetClients:        NewWorkflowClients,
		Excludes:          excludeGlobs,
		ErrorFactory:      errorFactory,
		SeverityThreshold: config.GetString(FlagSeverityThreshold),
		ReportConfig:      reportConfig,
	}
	c, err := NewCommand(args)
	if err != nil {
		return nil, errorFactory.NewGeneralSecretsFailureError(err, UnableToInitializeMsg)
	}

	logger.Info().Str(InputPathKey, inputPath).Msg("Running secrets workflow...")
	output, err := c.RunWorkflow(ctx, inputPath)
	if err != nil {
		return nil, errorFactory.NewGeneralSecretsFailureError(err, UnexpectedErrorMsg)
	}

	return output, nil
}

func buildReportConfig(config configuration.Configuration) ReportConfig {
	rc := ReportConfig{
		Report: config.GetBool(FlagReport),
	}

	if !rc.Report {
		return rc
	}

	rc.TargetName = config.GetString(FlagTargetName)
	rc.TargetReference = config.GetString(FlagTargetReference)
	rc.ProjectTags = config.GetString(FlagProjectTags)
	rc.ProjectBusinessCriticality = config.GetString(FlagProjectBusinessCriticality)
	rc.ProjectEnvironment = config.GetString(FlagProjectEnvironment)
	rc.ProjectLifecycle = config.GetString(FlagProjectLifecycle)

	orgName := config.GetString(configuration.ORGANIZATION_SLUG)
	web := config.GetString(configuration.WEB_APP_URL)
	if orgName != "" && web != "" {
		if projectPageURL, err := url.JoinPath(web, "org", orgName, "project"); err == nil {
			rc.ProjectPageURL = &projectPageURL
		}
	}

	return rc
}
