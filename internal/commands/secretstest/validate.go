package secretstest

import (
	"errors"
	"fmt"
	"strings"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"

	ff "github.com/snyk/cli-extension-secrets/pkg/filefilter"
)

var (
	validOptionsCriticality = map[string]struct{}{
		"critical": {}, "high": {}, "medium": {}, "low": {},
	}
	validOptionsProjectEnv = map[string]struct{}{
		"frontend": {}, "backend": {}, "internal": {}, "external": {}, "mobile": {}, "saas": {}, "onprem": {}, "hosted": {}, "distributed": {},
	}
	validOptionsProjectLifecycle = map[string]struct{}{
		"production": {}, "development": {}, "sandbox": {},
	}
)

type flagWithOptions struct {
	name         string
	allowEmpty   bool
	singleChoice bool
	validOptions map[string]struct{}
}

func validateFlagsConfig(config configuration.Configuration) error {
	// check --report related flags only if --report is true, otherwise flags are ignored
	err := validateReportConfig(config)
	if err != nil {
		return err
	}

	if config.IsSet(FlagSeverityThreshold) {
		flag := flagWithOptions{
			name:         FlagSeverityThreshold,
			allowEmpty:   false,
			singleChoice: true,
			validOptions: validOptionsCriticality,
		}
		err := validateFlagValue(config, flag)
		if err != nil {
			return err
		}
	}
	return nil
}

/*
This validates config flags that only work together with --report:
--project-environment, --project-business-criticality, --project-lifecycle
--project-tags.
*/
func validateReportConfig(config configuration.Configuration) error {
	if !config.GetBool(FlagReport) {
		return validateFlagsWithoutReportConfig(config)
	}

	flags := []flagWithOptions{
		{
			name:         FlagProjectEnvironment,
			allowEmpty:   false,
			validOptions: validOptionsProjectEnv,
		},
		{
			name:         FlagProjectLifecycle,
			allowEmpty:   false,
			validOptions: validOptionsProjectLifecycle,
		},
		{
			name:         FlagProjectBusinessCriticality,
			allowEmpty:   false,
			validOptions: validOptionsCriticality,
		},
	}

	for _, flag := range flags {
		if config.IsSet(flag.name) {
			err := validateFlagValue(config, flag)
			if err != nil {
				return err
			}
		}
	}

	return validateTags(config)
}

func validateFlagsWithoutReportConfig(config configuration.Configuration) error {
	reportFlags := []string{
		FlagTargetReference,
		FlagTargetName,
		FlagProjectEnvironment,
		FlagProjectLifecycle,
		FlagProjectBusinessCriticality,
		FlagProjectTags,
	}

	for _, flagName := range reportFlags {
		if config.IsSet(flagName) {
			errMsg := fmt.Sprintf("Invalid use of --%s, it can only be used in combination with the --report option", flagName)
			return errors.New(errMsg)
		}
	}
	return nil
}

/*
Validates a config flag that can only take one of a specific set of values
e.g. --severity-threshold must be one of low, medium, high, critical.
*/
func validateFlagValue(config configuration.Configuration, flag flagWithOptions) error {
	rawFlagValue := config.GetString(flag.name)
	if rawFlagValue == "" && flag.allowEmpty {
		return nil
	}

	rawValues := strings.Split(rawFlagValue, ",")

	if len(rawValues) > 1 && flag.singleChoice {
		errMsg := fmt.Sprintf("Invalid --%s, please use one of %s. ", flag.name, strings.Join(getKeys(flag.validOptions), " | "))
		return errors.New(errMsg)
	}

	var invalidValues []string
	for _, v := range rawValues {
		if _, exists := flag.validOptions[v]; !exists {
			invalidValues = append(invalidValues, v)
		}
	}

	if len(invalidValues) > 0 {
		errMsg := fmt.Sprintf("Invalid --%s: %v. Possible values are: %v.",
			flag.name, strings.Join(invalidValues, ", "),
			strings.Join(getKeys(flag.validOptions), ", "),
		)
		if flag.allowEmpty {
			errMsg += fmt.Sprintf("\nTo clear all existing values, pass no values i.e. %s=", flag.name)
		}
		return errors.New(errMsg)
	}

	return nil
}

/*
	This validates the --project-tags config flag

format: KEY=VALUE
*/
func validateTags(config configuration.Configuration) error {
	// no flag is set no need to validate
	if !config.IsSet(FlagProjectTags) {
		return nil
	}

	rawTags := config.GetString(FlagProjectTags)
	if rawTags == "" {
		return nil
	}

	// tags must have a specific KEY=VALUE format
	tags := strings.Split(rawTags, ",")
	for _, t := range tags {
		tagParts := strings.Split(t, "=")
		if len(tagParts) != 2 {
			errMsg := fmt.Sprintf("The tag %s does not have an \"=\" separating the key and value. For example: %s=KEY=VALUE", t, FlagProjectTags)
			errMsg += fmt.Sprintf("\nTo clear all existing values, pass no values i.e. %s=", FlagProjectTags)
			return errors.New(errMsg)
		}
	}

	return nil
}

func parseExcludeFlag(config configuration.Configuration) ([]string, error) {
	if !config.IsSet(FlagExcludeFilePath) {
		return nil, nil
	}

	rawExcludeFlag := strings.TrimSpace(config.GetString(FlagExcludeFilePath))
	if rawExcludeFlag == "" {
		return nil, errors.New("Empty --exclude argument. Did you mean --exclude=subdirectory?")
	}

	excludeGlobs, err := ff.ExpandExcludeNames(strings.Split(rawExcludeFlag, ","))
	if err != nil {
		return nil, cli_errors.NewValidationFailureError(
			"The --exclude argument must be a comma separated list of directory or file names and cannot contain a path.",
		)
	}
	return excludeGlobs, nil
}

func getKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
