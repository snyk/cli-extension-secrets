package secretstest

import "github.com/spf13/pflag"

const (
	FlagJSON                       = "json"
	FlagSARIF                      = "sarif"
	FlagJSONFileOutput             = "json-file-output"
	FlagSARIFFileOutput            = "sarif-file-output"
	FlagSeverityThreshold          = "severity-threshold"
	FlagIncludeIgnores             = "include-ignores"
	FlagExcludeFilePath            = "exclude"
	FlagReport                     = "report"
	FlagTargetReference            = "target-reference"
	FlagTargetName                 = "target-name"
	FlagProjectBusinessCriticality = "project-business-criticality"
	FlagProjectEnvironment         = "project-environment"
	FlagProjectLifecycle           = "project-lifecycle"
	FlagProjectTags                = "project-tags"
)

// TODO: ensure we have all required flags (use @ioana's doc).
func GetSecretsTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-secrets-test", pflag.ExitOnError)

	flagSet.Bool(FlagJSON, false, "Print results on the console as a JSON data structure.")
	flagSet.Bool(FlagSARIF, false, "Return results in SARIF format.")
	flagSet.String(FlagJSONFileOutput, "",
		"Save test output as a JSON data structure directly to the specified file, regardless of whether or not you use the --json option.")
	flagSet.String(FlagSARIFFileOutput, "",
		"Save test output in SARIF format directly to the specified file, regardless of whether or not you use the --sarif option.")
	flagSet.String(FlagSeverityThreshold, "", "Report only vulnerabilities at the specified level or higher.")
	flagSet.Bool(FlagIncludeIgnores, false, "Shows all discovered issues, including any that have been previously ignored.")
	flagSet.String(FlagExcludeFilePath, "", "Ignores all issues originating from the specified file path.")
	flagSet.Bool(FlagReport, false, "Share results with the Snyk Web UI.")
	flagSet.String(FlagTargetName, "", "Used in Share Results to set or override the project name for the repository. ")
	flagSet.String(FlagTargetReference, "", "Used in Share Results to specify a reference which differentiates this project, e.g. a branch name or version.")
	flagSet.String(FlagProjectBusinessCriticality, "", "Set the project business criticality project attribute to one or more values (comma-separated).")
	flagSet.String(FlagProjectEnvironment, "", "Set the project environment project attribute to one or more values (comma-separated).")
	flagSet.String(FlagProjectLifecycle, "", "Set the project lifecycle project attribute to one or more values (comma-separated).")
	flagSet.String(FlagProjectTags, "", "Set the project tags to one or more values (comma-separated key value pairs with an \"=\" separator).")

	return flagSet
}
