package instrumentation

import (
	"time"

	"github.com/snyk/go-application-framework/pkg/analytics"
)

// Custom metric keys.
const (
	SecretsAnalysisTimeMs   string = "secretsAnalysisTimeMs"
	SecretsFileUploadTimeMs string = "secretsFileUploadMs"
	SecretsFileFilterTimeMs string = "secretsFileFilterMs"
	SecretsSizeFiltered     string = "secretsSizeFiltered"
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
func NewGAFInstrumentation(analytics analytics.Analytics) *GAFInstrumentation {
	return &GAFInstrumentation{analytics}
}

type GAFInstrumentation struct {
	analytics analytics.Analytics
}

// RecordTime is used to record the time it takes to do the code analysis.
func (i *GAFInstrumentation) RecordTime(key string, startTime time.Time) {
	i.analytics.AddExtensionIntegerValue(key, int(time.Since(startTime).Milliseconds()))
}

func (i *GAFInstrumentation) RecordAnalysisTimeMs(startTime time.Time) {
	i.RecordTime(SecretsAnalysisTimeMs, startTime)
}

func (i *GAFInstrumentation) RecordFileUploadTimeMs(startTime time.Time) {
	i.RecordTime(SecretsFileUploadTimeMs, startTime)
}

func (i *GAFInstrumentation) RecordFileFilterTimeMs(startTime time.Time) {
	i.RecordTime(SecretsFileFilterTimeMs, startTime)
}

func (i *GAFInstrumentation) RecordSizeFiltered(total int) {
	i.analytics.AddExtensionIntegerValue(SecretsSizeFiltered, total)
}
