package secretstest

import (
	"context"
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/internal/clients/upload"
)

// TitleUploadingHistory is the progress bar title shown while the git bundle is uploaded.
const TitleUploadingHistory = "Uploading git history..."

type newLargeFileClientFunc func(workflow.InvocationContext, string) (upload.LargeFileClient, error)

// NewHistoryClient creates the large file upload client needed for the history workflow.
//
//nolint:ireturn // returns the interface so tests can substitute the client.
func NewHistoryClient(ictx workflow.InvocationContext, orgID string) (upload.LargeFileClient, error) {
	client, err := upload.NewLargeFileClient(ictx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to create large file upload client: %w", err)
	}
	return client, nil
}

// HistoryArgs holds the arguments required to run the history workflow.
type HistoryArgs struct {
	InvocationContext workflow.InvocationContext
	UserInterface     UserInterface
	GetClient         newLargeFileClientFunc
	ErrorFactory      *ErrorFactory
	// Scanner triggers the scan of the uploaded revision and formats its results.
	Scanner    *Command
	OrgID      string
	BundlePath string
}

// HistoryWorkflow uploads the git bundle at args.BundlePath as a new revision, scans it and returns the formatted results.
func HistoryWorkflow(ctx context.Context, args *HistoryArgs) ([]workflow.Data, error) {
	logger := args.InvocationContext.GetEnhancedLogger()

	info, err := os.Stat(args.BundlePath)
	if err != nil {
		return nil, args.ErrorFactory.NewValidationFailureError(
			fmt.Sprintf("Unable to read the git bundle at '%s': %s", args.BundlePath, err.Error()))
	}
	if !info.Mode().IsRegular() {
		return nil, args.ErrorFactory.NewValidationFailureError(
			fmt.Sprintf("The --%s option expects the path to a git bundle file, but '%s' is not a file.", FlagHistory, args.BundlePath))
	}

	client, err := args.GetClient(args.InvocationContext, args.OrgID)
	if err != nil {
		return nil, args.ErrorFactory.NewGeneralSecretsFailureError(err, UnableToInitializeMsg)
	}

	args.UserInterface.SetTitle(TitleUploadingHistory)
	result, err := client.CreateRevisionFromLargeFile(ctx, args.BundlePath)
	if err != nil {
		return nil, args.ErrorFactory.NewUploadError(err)
	}

	logger.Info().
		Str("revisionID", result.RevisionID.String()).
		Int64("size", result.Size).
		Int("parts", result.ChunkCount).
		Msg("Uploaded git bundle")

	// Print the revision ID so it can be reused even if the scan fails.
	if err = args.InvocationContext.GetUserInterface().Output(fmt.Sprintf("Revision ID: %s\n", result.RevisionID)); err != nil {
		logger.Err(err).Msg("Failed to print revision ID")
	}

	args.UserInterface.SetTitle(TitleScanning)
	testResult, err := args.Scanner.triggerScan(ctx, result.RevisionID.String())
	if err != nil {
		return nil, err
	}

	args.UserInterface.SetTitle(TitleRetrievingResults)
	output, err := args.Scanner.prepareOutput(ctx, testResult)
	if err != nil {
		return nil, args.ErrorFactory.NewPrepareOutputError(err)
	}

	return output, nil
}
