package secretstest

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	upload_errors "github.com/snyk/error-catalog-golang-public/uploadrevision"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	gafutils "github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/cli-extension-secrets/internal/staging"
)

// User-facing error messages.
const (
	UnableToInitializeMsg  = "Unable to initialize command."
	UnexpectedErrorMsg     = "An unexpected error occurred."
	FeatureNotEnabledMsg   = "Snyk Secrets is not supported for org %s: enable it in Settings > Snyk Secrets"
	SecretsEnabledCheckMsg = "Unable to check if the Secrets feature is enabled."
	OrgResolutionMsg       = "Unable to determine the organization."
	NoOrgProvidedMsg       = "No org provided."
	SingleInputPathMsg     = "Only one input path is accepted."
	AbsPathFailureMsg      = "Unable to get absolute path."

	// Staging failures. A history scan writes hunks to a staging directory
	// before uploading them, and each way that can fail has a different remedy,
	// so none of them should reach the user as a generic scan failure.
	StagingNoSpaceMsg     = "Not enough disk space to scan the git history. Free up space, or set SNYK_TMP_PATH to a location on a volume with more space."
	StagingPathTooLongMsg = "The temporary directory path is too long to scan the git history. Set SNYK_TMP_PATH to a shorter path."
	StagingUnavailableMsg = "Unable to create a temporary directory to scan the git history. " +
		"Check the permissions on the Snyk cache directory, or set SNYK_TMP_PATH to a writable location."
)

// ErrorFactory creates errors for the Secrets extension.
type ErrorFactory struct {
	logger *zerolog.Logger
}

// NewErrorFactory creates a new ErrorFactory.
func NewErrorFactory(logger *zerolog.Logger) *ErrorFactory {
	return &ErrorFactory{
		logger: logger,
	}
}

// NewRevisionError wraps an upload revision creation failure.
func (ef *ErrorFactory) NewRevisionError(err error) error {
	return ef.ensureCatalogError(err, "error creating upload revision")
}

// NewExecuteTestError wraps a test execution failure.
func (ef *ErrorFactory) NewExecuteTestError(err error) error {
	return ef.ensureCatalogError(err, "error executing test")
}

// NewTestResourceError wraps a test resource creation failure.
func (ef *ErrorFactory) NewTestResourceError(err error) error {
	return ef.ensureCatalogError(err, "error creating test resource")
}

// NewPrepareOutputError wraps an output preparation failure.
func (ef *ErrorFactory) NewPrepareOutputError(err error) error {
	return ef.ensureCatalogError(err, "failed to prepare output")
}

// NewGeneralSecretsFailureError wraps a generic secrets workflow failure.
func (ef *ErrorFactory) NewGeneralSecretsFailureError(err error, msg string) error {
	return ef.ensureCatalogError(err, msg)
}

// NewSecretsEnabledCheckError wraps a failure to resolve the Secrets settings.
// Resolving the setting triggers an authenticated API call to the REST
// settings endpoint, so the underlying error is often an authentication failure.
func (ef *ErrorFactory) NewSecretsEnabledCheckError(err error) error {
	return ef.ensureCatalogError(err, SecretsEnabledCheckMsg)
}

// NewOrgResolutionError wraps a failure to resolve the organization.
func (ef *ErrorFactory) NewOrgResolutionError(err error) error {
	return ef.ensureCatalogError(err, OrgResolutionMsg)
}

// NewFeatureNotEnabledError returns an error indicating the feature flag is disabled.
func (ef *ErrorFactory) NewFeatureNotEnabledError(msg string) error {
	return cli_errors.NewFeatureNotEnabledError(msg)
}

// NewFeatureUnderDevelopmentError returns an error indicating the feature is not yet available.
func (ef *ErrorFactory) NewFeatureUnderDevelopmentError(msg string) error {
	return cli_errors.NewFeatureUnderDevelopmentError(msg)
}

// NewValidationFailureError returns an error for invalid user input.
func (ef *ErrorFactory) NewValidationFailureError(msg string) error {
	return cli_errors.NewValidationFailureError(msg)
}

// NewInvalidFlagError returns an error for an unrecognized or invalid CLI flag.
func (ef *ErrorFactory) NewInvalidFlagError(err error) error {
	return cli_errors.NewInvalidFlagOptionError(err.Error(), snyk_errors.WithCause(err))
}

// NewUploadError maps file-upload errors to the appropriate catalog error type.
func (ef *ErrorFactory) NewUploadError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, fileupload.ErrNoFilesProvided) {
		return cli_errors.NewNoSupportedFilesFoundError(
			"No supported files found.",
			snyk_errors.WithCause(err),
		)
	}

	var limitErr *fileupload.FileCountLimitError
	if errors.As(err, &limitErr) {
		return upload_errors.NewFileCountLimitExceededError(
			fmt.Sprintf("File count limit reached: %s", limitErr),
			snyk_errors.WithCause(err),
		)
	}

	var totalSizeErr *fileupload.TotalPayloadSizeLimitError
	if errors.As(err, &totalSizeErr) {
		return upload_errors.NewTotalFilesSizeLimitExceededError(
			totalSizeErr.Error(),
			snyk_errors.WithCause(err),
		)
	}

	var singleSizeErr *fileupload.FileSizeLimitError
	if errors.As(err, &singleSizeErr) {
		return upload_errors.NewFileTooLargeError(
			singleSizeErr.Error(),
			snyk_errors.WithCause(err),
		)
	}
	return ef.NewRevisionError(err)
}

// NewStagingError maps a staging failure to a user-facing error.
//
// Each case names the concrete remedy, because the user can fix all of them.
// The catalog has no CLI-side entry for "out of disk space" or "path too long",
// so these currently reuse the general secrets failure code; a dedicated
// catalog entry would let the UI and analytics tell them apart.
func (ef *ErrorFactory) NewStagingError(err error) error {
	if err == nil {
		return nil
	}

	var insufficientSpace *gafutils.ErrInsufficientDiskSpace
	switch {
	case errors.As(err, &insufficientSpace):
		return ef.stagingFailure(err, StagingNoSpaceMsg, map[string]any{
			"required_bytes":  insufficientSpace.Requested,
			"available_bytes": insufficientSpace.Available,
		})
	case errors.Is(err, staging.ErrPathTooLong):
		return ef.stagingFailure(err, StagingPathTooLongMsg, nil)
	case errors.Is(err, staging.ErrUnavailable):
		return ef.stagingFailure(err, StagingUnavailableMsg, nil)
	default:
		return ef.ensureCatalogError(err, "failed to stage git history")
	}
}

func (ef *ErrorFactory) stagingFailure(cause error, msg string, meta map[string]any) error {
	ef.logger.Error().Err(cause).Msg(msg)

	catalogErr := cli_errors.NewGeneralSecretsFailureError(msg, snyk_errors.WithCause(cause))
	if len(meta) == 0 {
		return catalogErr
	}

	// Not wrapped: this returns the same catalog error with metadata attached, and
	// wrapping it would hide the catalog error from the CLI's error presenter.
	//nolint:wrapcheck // see above
	return gafutils.AddMetaDataToErr(catalogErr, meta)
}

func (ef *ErrorFactory) ensureCatalogError(err error, logMsg string) error {
	/* Don't wrap an error if is already a presentable snyk_error
	 * If we wrap a specific error (upload_errors) with a generic one here,
	 * the CLI will only display the outer generic message (latest catalog error wins),
	 * causing the user to lose the specific context and actionable guidance.
	 */
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) {
		ef.logger.Error().Err(snykErr.Cause).Msg(snykErr.Detail)
		return err
	}
	ef.logger.Error().Err(err).Msg(logMsg)

	return cli_errors.NewGeneralSecretsFailureError(
		fmt.Sprintf("Workflow execution failed: %s.", logMsg),
		snyk_errors.WithCause(err),
	)
}
