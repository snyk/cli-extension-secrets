// Package instrumentation provides analytics recording for the secrets workflow.
package instrumentation

import (
	"time"

	"github.com/snyk/go-application-framework/pkg/analytics"
)

// Custom metric keys.
const (
	SecretsAnalysisTimeMs   string = "analysisTimeMs"
	SecretsFileUploadTimeMs string = "fileUploadMs"
	SecretsFileFilterTimeMs string = "fileFilterMs"
	SecretsSizeFiltered     string = "sizeFiltered"
	SecretsGitBundleTimeMs  string = "gitBundleMs"
	SecretsGitBundleSizeMB  string = "gitBundleMB"
	SecretsGitHistoryScan   string = "gitHistoryScan"
)

// Instrumentation defines the interface that we expect for instrumentation objects.
type Instrumentation interface {
	RecordSizeFiltered(total int)
	RecordAnalysisTimeMs(startTime time.Time)
	RecordFileUploadTimeMs(startTime time.Time)
	RecordFileFilterTimeMs(startTime time.Time)
	RecordGitBundleTimeMs(startTime time.Time)
	RecordGitBundleSizeMB(sizeBytes int64)
	RecordGitHistoryScan()

	RecordTime(key string, startTime time.Time)
}

// NewGAFInstrumentation will create a new GAFInstrumentation based on the provided GAF analytics.
func NewGAFInstrumentation(a analytics.Analytics) *GAFInstrumentation {
	return &GAFInstrumentation{a}
}

// GAFInstrumentation records timing and size metrics via the GAF analytics API.
type GAFInstrumentation struct {
	analytics analytics.Analytics
}

// RecordTime is used to record the time it takes to do the code analysis.
func (i *GAFInstrumentation) RecordTime(key string, startTime time.Time) {
	i.analytics.AddExtensionIntegerValue(key, int(time.Since(startTime).Milliseconds()))
}

// RecordAnalysisTimeMs records the duration of the secrets analysis phase.
func (i *GAFInstrumentation) RecordAnalysisTimeMs(startTime time.Time) {
	i.RecordTime(SecretsAnalysisTimeMs, startTime)
}

// RecordFileUploadTimeMs records the duration of the file upload phase.
func (i *GAFInstrumentation) RecordFileUploadTimeMs(startTime time.Time) {
	i.RecordTime(SecretsFileUploadTimeMs, startTime)
}

// RecordFileFilterTimeMs records the duration of the file filtering phase.
func (i *GAFInstrumentation) RecordFileFilterTimeMs(startTime time.Time) {
	i.RecordTime(SecretsFileFilterTimeMs, startTime)
}

// RecordSizeFiltered records the number of files excluded by size filtering.
func (i *GAFInstrumentation) RecordSizeFiltered(total int) {
	i.analytics.AddExtensionIntegerValue(SecretsSizeFiltered, total)
}

// RecordGitBundleTimeMs records the duration of packaging the git history into a bundle.
func (i *GAFInstrumentation) RecordGitBundleTimeMs(startTime time.Time) {
	i.RecordTime(SecretsGitBundleTimeMs, startTime)
}

// RecordGitBundleSizeMB records the size of the git history bundle in megabytes, given its size in bytes.
// The value is rounded up, so a non-empty bundle is never reported as 0.
func (i *GAFInstrumentation) RecordGitBundleSizeMB(sizeBytes int64) {
	const bytesPerMB = 1024 * 1024
	// It rounds up, so a 200 KB bundle shows as 1 MB and is never 0.
	i.analytics.AddExtensionIntegerValue(SecretsGitBundleSizeMB, int((sizeBytes+bytesPerMB-1)/bytesPerMB))
}

// RecordGitHistoryScan marks the run as a git history scan, so that its upload and analysis timings
// can be told apart from those of a regular file scan.
func (i *GAFInstrumentation) RecordGitHistoryScan() {
	i.analytics.AddExtensionBoolValue(SecretsGitHistoryScan, true)
}
