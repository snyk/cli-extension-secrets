package secretstest

import "github.com/spf13/pflag"

const (
	FlagReport            = "report"
	FlagJSON              = "json"
	FlagSARIF             = "sarif"
	FlagJSONFileOutput    = "json-file-output"
	FlagSARIFFileOutput   = "sarif-file-output"
	FlagSeverityThreshold = "severity-threshold"
)

// TODO: ensure we have all required flags (use @ioana's doc).
func GetSecretsTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-secrets-test", pflag.ExitOnError)

	flagSet.Bool(FlagReport, false, "Share results with the Snyk Web UI.")
	flagSet.Bool(FlagJSON, false, "Print results on the console as a JSON data structure.")
	flagSet.Bool(FlagSARIF, false, "Return results in SARIF format.")
	flagSet.String(FlagJSONFileOutput, "",
		"Save test output as a JSON data structure directly to the specified file, regardless of whether or not you use the --json option.")
	flagSet.String(FlagSARIFFileOutput, "",
		"Save test output in SARIF format directly to the specified file, regardless of whether or not you use the --sarif option.")
	flagSet.String(FlagSeverityThreshold, "", "Report only vulnerabilities at the specified level or higher.")
	return flagSet
}
