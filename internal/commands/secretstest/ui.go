package secretstest

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Progress bar titles shown during the secrets workflow.
const (
	TitleScanning          = "Scanning..."
	TitleValidating        = "Validating configuration..."
	TitleRetrievingResults = "Retrieving results..."
)

// UserInterface abstracts progress-bar operations for the secrets workflow.
type UserInterface interface {
	SetTitle(title string)
	Clear()
}

// CLIUserInterface implements UserInterface using the GAF progress bar.
type CLIUserInterface struct {
	logger      *zerolog.Logger
	progressbar ui.ProgressBar
}

// NewUI creates a CLIUserInterface from the given invocation context.
func NewUI(ictx workflow.InvocationContext) *CLIUserInterface {
	return &CLIUserInterface{
		logger:      ictx.GetEnhancedLogger(),
		progressbar: ictx.GetUserInterface().NewProgressBar(),
	}
}

// SetTitle updates the progress bar title and triggers a render.
func (u *CLIUserInterface) SetTitle(title string) {
	u.progressbar.SetTitle(title)
	err := u.progressbar.UpdateProgress(ui.InfiniteProgress)
	if err != nil {
		u.logger.Err(err).Msg("Failed to update progress")
		return
	}
}

// Clear removes the progress bar from the terminal.
func (u *CLIUserInterface) Clear() {
	err := u.progressbar.Clear()
	if err != nil {
		u.logger.Err(err).Msg("Failed to clear progress")
		return
	}
}
