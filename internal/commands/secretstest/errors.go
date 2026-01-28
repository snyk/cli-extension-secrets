package secretstest

import (
	"fmt"

	"github.com/rs/zerolog"
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
	ef.logger.Error().Err(err).Msg("error initialize client")
	return fmt.Errorf("client init error: %w", err)
}

func (ef *ErrorFactory) CreateRevisionError(err error) error {
	ef.logger.Error().Err(err).Msg("error creating upload revision")
	return fmt.Errorf("error creating upload revision: %w", err)
}

func (ef *ErrorFactory) ExecuteTestError(err error) error {
	ef.logger.Error().Err(err).Msg("error executing test")
	return fmt.Errorf("error executing test: %w", err)
}

func (ef *ErrorFactory) CreateTestResourceError(err error) error {
	ef.logger.Error().Err(err).Msg("error creating test resource")
	return fmt.Errorf("error creating test resource: %w", err)
}

func (ef *ErrorFactory) CreateNoSupportedFilesFoundError() error {
	ef.logger.Error().Msg("no supported files found")
	return fmt.Errorf("no supported files found")
}

func (ef *ErrorFactory) CreateFileCountLimitExceededError(err error) error {
	ef.logger.Error().Msg("file count limit exceeded")
	return fmt.Errorf("file count limit exceeded: %w", err)
}
