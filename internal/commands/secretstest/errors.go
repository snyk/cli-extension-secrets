package secretstest

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	upload_errors "github.com/snyk/error-catalog-golang-public/uploadrevision"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
)

// User-facing error messages.
const (
	UnableToInitializeMsg = "Unable to initialize command."
	UnexpectedErrorMsg    = "An unexpected error occurred."
	FeatureNotEnabledMsg  = "User not allowed to run without feature flag."
	JSONNotSupportedMsg   = "Flag --json is not yet supported."
	SARIFNotSupportedMsg  = "Flag --sarif is not yet supported."
	NoOrgProvidedMsg      = "No org provided."
	SingleInputPathMsg    = "Only one input path is accepted."
	AbsPathFailureMsg     = "Unable to get absolute path."
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
