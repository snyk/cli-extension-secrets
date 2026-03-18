package secretstest

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/snyk/cli-extension-secrets/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-secrets/internal/instrumentation"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	FeatureFlagIsSecretsEnabled = "internal_snyk_feature_flag_is_secrets_enabled" //nolint:gosec // config key
)

var WorkflowID = workflow.NewWorkflowIdentifier("secrets.test")

func RegisterWorkflows(e workflow.Engine) error {
	flagSet := GetSecretsTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(flagSet)

	if _, err := e.Register(WorkflowID, c, SecretsWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}

	config_utils.AddFeatureFlagToConfig(e, FeatureFlagIsSecretsEnabled, "isSecretsEnabled")

	return nil
}

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

	if !config.GetBool(FeatureFlagIsSecretsEnabled) {
		return nil, errorFactory.NewFeatureNotEnabledError(FeatureNotEnabledMsg)
	}

	if msg, unsupported := validateUnsupportedFlags(config); unsupported {
		return nil, errorFactory.NewFeatureUnderDevelopmentError(msg)
	}

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, errorFactory.NewValidationFailureError(NoOrgProvidedMsg)
	}

	err := validateFlagsConfig(config)
	if err != nil {
		return nil, errorFactory.NewValidationFailureError(err.Error())
	}

	severityThreshold := config.GetString(FlagSeverityThreshold)

	inputPaths := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(inputPaths) != 1 {
		return nil, errorFactory.NewValidationFailureError(SingleInputPathMsg)
	}

	inputPath, err := filepath.Abs(inputPaths[0])
	if err != nil {
		absErr := fmt.Errorf("could not get absolute path '%s': %w", inputPaths[0], err)
		return nil, errorFactory.NewGeneralSecretsFailureError(absErr, AbsPathFailureMsg)
	}

	inputPath = sanitizePath(inputPath)
	gitRootDir, err := findGitRoot(inputPath)
	if err != nil {
		logger.Err(err).Str("inputPath", inputPath).Msg("could not determine common git root")
	}

	inputPathRelativeToGitRoot, err := computeRelativeInput(inputPath, gitRootDir)
	if err != nil {
		logger.Err(err).Str("inputPathRelativeToGitRoot", inputPathRelativeToGitRoot).Msg("could not determine common repo root")
	}

	remoteRepoURLFlag := config.GetString(FlagRemoteRepoURL)
	repoURL, err := findRepoURLWithOverride(gitRootDir, remoteRepoURLFlag)
	if err != nil {
		logger.Err(err).Str("remoteRepoURLFlag", remoteRepoURLFlag).Str("inputPath", inputPath).Msg("could not compute gitRoot or repoURL")
	}

	branch, err := findBranchName(gitRootDir)
	if err != nil {
		logger.Warn().Err(err).Msg("could not determine git branch")
	}

	commitRef, err := findCommitRef(gitRootDir)
	if err != nil {
		logger.Warn().Err(err).Msg("could not determine git commit ref")
	}

	excludeGlobs, err := parseExcludeFlag(config)
	if err != nil {
		return nil, errorFactory.NewInvalidFlagError(err)
	}

	reportConfig := buildReportConfig(config)

	args := &CommandArgs{
		InvocationContext: ictx,
		UserInterface:     u,
		OrgID:             orgID,
		RootFolderID:      inputPathRelativeToGitRoot,
		RepoURL:           repoURL,
		Branch:            branch,
		CommitRef:         commitRef,
		GetClients:        NewWorkflowClients,
		Excludes:          excludeGlobs,
		ErrorFactory:      errorFactory,
		SeverityThreshold: severityThreshold,
		ReportConfig:      reportConfig,
	}
	c, err := NewCommand(args)
	if err != nil {
		return nil, errorFactory.NewGeneralSecretsFailureError(err, UnableToInitializeMsg)
	}

	logger.Info().Str("inputPath", inputPath).Msg("Running secrets workflow...")
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

	return rc
}
