package secretstest

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	TitleScanning          = "Scanning..."
	TitleValidating        = "Validating configuration..."
	TitleRetrievingResults = "Retrieving results..."
)

type UserInterface interface {
	SetTitle(title string)
	Clear()
}
type CLIUserInterface struct {
	logger      *zerolog.Logger
	progressbar ui.ProgressBar
}

func NewUI(ictx workflow.InvocationContext) *CLIUserInterface {
	return &CLIUserInterface{
		logger:      ictx.GetEnhancedLogger(),
		progressbar: ictx.GetUserInterface().NewProgressBar(),
	}
}

func (u *CLIUserInterface) SetTitle(title string) {
	u.progressbar.SetTitle(title)
	err := u.progressbar.UpdateProgress(ui.InfiniteProgress)
	if err != nil {
		u.logger.Err(err).Msg("Failed to update progress")
		return
	}
}

func (u *CLIUserInterface) Clear() {
	err := u.progressbar.Clear()
	if err != nil {
		u.logger.Err(err).Msg("Failed to clear progress")
		return
	}
}
