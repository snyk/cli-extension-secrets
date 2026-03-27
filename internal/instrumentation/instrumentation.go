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
)

// Instrumentation defines the interface that we expect for instrumentation objects.
type Instrumentation interface {
	RecordSizeFiltered(total int)
	RecordAnalysisTimeMs(startTime time.Time)
	RecordFileUploadTimeMs(startTime time.Time)
	RecordFileFilterTimeMs(startTime time.Time)

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
