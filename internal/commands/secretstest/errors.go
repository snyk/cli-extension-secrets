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

const UnableToInitializeError = "Unable to initialize."

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

func (ef *ErrorFactory) ClientInitError(err error) error {
	return ef.ensureCatalogError(err, "client init error")
}

func (ef *ErrorFactory) CreateRevisionError(err error) error {
	return ef.ensureCatalogError(err, "error creating upload revision")
}

func (ef *ErrorFactory) ExecuteTestError(err error) error {
	return ef.ensureCatalogError(err, "error executing test")
}

func (ef *ErrorFactory) CreateTestResourceError(err error) error {
	return ef.ensureCatalogError(err, "error creating test resource")
}

func (ef *ErrorFactory) CreatePrepareOutputError(err error) error {
	outputErr := fmt.Errorf("failed to prepare output: %w", err)
	return ef.ensureCatalogError(outputErr, "failed to prepare output")
}

func (ef *ErrorFactory) CreateGeneralSecretsFailureError(err error) error {
	return ef.ensureCatalogError(err, "an unexpected error occurred")
}

func (ef *ErrorFactory) CreateUploadError(err error) error {
	if err == nil {
		return nil
	}
	ef.logger.Error().Err(err).Msg("file upload failed")

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
	return ef.CreateRevisionError(err)
}

func (ef *ErrorFactory) ensureCatalogError(err error, logMsg string) error {
	/* Don't wrap an error if is already a presentable snyk_error
	 * If we wrap a specific error (upload_errors) with a generic one here,
	 * the CLI will only display the outer generic message (latest catalog error wins),
	 * causing the user to lose the specific context and actionable guidance.
	 */
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) {
		return err
	}

	ef.logger.Error().Err(err).Msg(logMsg)
	return cli_errors.NewGeneralSecretsFailureError(
		fmt.Sprintf("Workflow execution failed: %s.", logMsg),
		snyk_errors.WithCause(err),
	)
}
