package secretstest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateAndPrepareInput_SecretsEnablement covers the "feature flag OR
// settings" enablement gate in validateAndPrepareInput: the feature flag can
// short-circuit to "enabled", otherwise the REST setting is authoritative and
// its lookup errors are surfaced rather than masked as "feature not enabled".
func TestValidateAndPrepareInput_SecretsEnablement(t *testing.T) {
	orgID := uuid.New().String()

	// returnErr builds a default-value callback that fails resolution, mimicking
	// a feature-flag / settings lookup that errors (e.g. an API call failure).
	returnErr := func(err error) func(configuration.Configuration, any) (any, error) {
		return func(_ configuration.Configuration, _ any) (any, error) {
			return false, fmt.Errorf("lookup failed: %w", err)
		}
	}
	authErr := snyk.NewUnauthorisedError("Use `snyk auth` to authenticate.")

	testCases := []struct {
		desc        string
		setup       func(c configuration.Configuration)
		wantEnabled bool   // true => enablement gate passes (validation succeeds)
		wantErrCode string // expected catalog ErrorCode when the gate blocks
		wantDetail  string // expected substring in the catalog error Detail
	}{
		{
			desc: "feature flag enabled, setting disabled -> enabled",
			setup: func(c configuration.Configuration) {
				c.Set(FeatureFlagIsSecretsEnabled, true)
				c.Set(SecretsSettingsEnabled, false)
			},
			wantEnabled: true,
		},
		{
			desc: "feature flag disabled, setting enabled -> enabled",
			setup: func(c configuration.Configuration) {
				c.Set(FeatureFlagIsSecretsEnabled, false)
				c.Set(SecretsSettingsEnabled, true)
			},
			wantEnabled: true,
		},
		{
			desc: "feature flag enabled, setting enabled -> enabled",
			setup: func(c configuration.Configuration) {
				c.Set(FeatureFlagIsSecretsEnabled, true)
				c.Set(SecretsSettingsEnabled, true)
			},
			wantEnabled: true,
		},
		{
			desc: "feature flag disabled, setting disabled -> not enabled",
			setup: func(c configuration.Configuration) {
				c.Set(FeatureFlagIsSecretsEnabled, false)
				c.Set(SecretsSettingsEnabled, false)
			},
			wantErrCode: "SNYK-CLI-0016",
			wantDetail:  fmt.Sprintf(FeatureNotEnabledMsg, orgID),
		},
		{
			desc: "feature flag errors, setting enabled -> enabled (flag error ignored)",
			setup: func(c configuration.Configuration) {
				c.AddDefaultValue(FeatureFlagIsSecretsEnabled, returnErr(authErr))
				c.Set(SecretsSettingsEnabled, true)
			},
			wantEnabled: true,
		},
		{
			desc: "feature flag errors, setting disabled -> not enabled",
			setup: func(c configuration.Configuration) {
				c.AddDefaultValue(FeatureFlagIsSecretsEnabled, returnErr(authErr))
				c.Set(SecretsSettingsEnabled, false)
			},
			wantErrCode: "SNYK-CLI-0016",
			wantDetail:  fmt.Sprintf(FeatureNotEnabledMsg, orgID),
		},
		{
			desc: "feature flag disabled, setting errors with auth error -> surfaces auth error",
			setup: func(c configuration.Configuration) {
				c.Set(FeatureFlagIsSecretsEnabled, false)
				c.AddDefaultValue(SecretsSettingsEnabled, returnErr(authErr))
			},
			wantErrCode: "SNYK-0005",
		},
		{
			desc: "feature flag disabled, setting errors with generic error -> wrapped check error",
			setup: func(c configuration.Configuration) {
				c.Set(FeatureFlagIsSecretsEnabled, false)
				c.AddDefaultValue(SecretsSettingsEnabled, returnErr(errors.New("boom")))
			},
			wantDetail: SecretsEnabledCheckMsg,
		},
		{
			desc: "feature flag enabled short-circuits the failing setting lookup -> enabled",
			setup: func(c configuration.Configuration) {
				c.Set(FeatureFlagIsSecretsEnabled, true)
				c.AddDefaultValue(SecretsSettingsEnabled, returnErr(errors.New("boom")))
			},
			wantEnabled: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := configuration.New()
			config.Set(configuration.ORGANIZATION, orgID)
			config.Set(configuration.INPUT_DIRECTORY, []string{"."})
			tc.setup(config)

			logger := zerolog.Nop()
			errorFactory := NewErrorFactory(&logger)

			gotOrgID, gotPath, err := validateAndPrepareInput(config, errorFactory)

			if tc.wantEnabled {
				require.NoError(t, err, "enablement gate should pass and validation should succeed")
				assert.Equal(t, orgID, gotOrgID)
				assert.NotEmpty(t, gotPath)
				return
			}

			catalogErr := requireCatalogError(t, err)
			if tc.wantErrCode != "" {
				assert.Equal(t, tc.wantErrCode, catalogErr.ErrorCode)
			}
			if tc.wantDetail != "" {
				assert.Contains(t, catalogErr.Detail, tc.wantDetail)
			}
			assert.NotContains(t, catalogErr.Detail, SingleInputPathMsg,
				"the enablement gate should block before reaching later validation")
		})
	}
}

func TestValidateFlagValue(t *testing.T) {
	type testInput struct {
		config map[string]any
		flag   flagWithOptions
	}

	testCases := []struct {
		in     testInput
		hasErr bool
		desc   string
	}{
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: optionBackend,
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{optionBackend: {}, optionFrontend: {}},
					allowEmpty:   true,
				},
			},
			hasErr: false,
			desc:   "valid flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: optionBackend + "," + optionBackend,
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{optionBackend: {}, optionFrontend: {}},
					allowEmpty:   true,
				},
			},
			hasErr: false,
			desc:   "multiple valid flags",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{optionBackend: {}, optionFrontend: {}},
					allowEmpty:   true,
				},
			},
			hasErr: false,
			desc:   "valid empty flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{optionBackend: {}, optionFrontend: {}},
					allowEmpty:   false,
				},
			},
			hasErr: true,
			desc:   "invalid empty flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "invalid-value",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{optionBackend: {}, optionFrontend: {}},
					allowEmpty:   true,
				},
			},
			hasErr: true,
			desc:   "invalid flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "invalid-value!tc=,",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{optionBackend: {}, optionFrontend: {}},
					allowEmpty:   true,
				},
			},
			hasErr: true,
			desc:   "invalid flag format",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: optionBackend,
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{optionBackend: {}, optionFrontend: {}},
					allowEmpty:   true,
					singleChoice: true,
				},
			},
			hasErr: false,
			desc:   "valid flag with single choice",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: optionBackend + ",frontend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{optionBackend: {}, optionFrontend: {}},
					allowEmpty:   true,
					singleChoice: true,
				},
			},
			hasErr: true,
			desc:   "invalid flag with single choice",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in.config)

			err := validateFlagValue(config, tc.in.flag)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateTags(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in:     map[string]any{},
			hasErr: false,
			desc:   "no --tags or --project-tags set, no validation needed",
		},
		{
			in: map[string]any{
				FlagProjectTags: "env=dev,stage=first",
			},
			hasErr: false,
			desc:   "valid --project-tags",
		},
		{
			in: map[string]any{
				FlagProjectTags: "",
			},
			hasErr: false,
			desc:   "valid empty --tags",
		},
		{
			in: map[string]any{
				FlagProjectTags: "env=dev,test",
			},
			hasErr: true,
			desc:   "invalid --project-tags",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateTags(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateReportConfig(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in: map[string]any{
				FlagProjectEnvironment: "invalid-env",
				FlagReport:             true,
			},
			hasErr: true,
			desc:   "invalid --project-environment with --report",
		},
		{
			in: map[string]any{
				FlagProjectLifecycle: "invalid-lifecycle",
				FlagReport:           true,
			},
			hasErr: true,
			desc:   "invalid --project-lifecycle with --report",
		},
		{
			in: map[string]any{
				FlagProjectBusinessCriticality: "invalid-business-criticality",
				FlagReport:                     true,
			},
			hasErr: true,
			desc:   "invalid --project-business-criticality with --report",
		},
		{
			in: map[string]any{
				FlagProjectTags: "invalid-tags",
				FlagReport:      true,
			},
			hasErr: true,
			desc:   "invalid --project-tags with --report",
		},
		{
			in: map[string]any{
				FlagProjectTags:                "env=dev,stage=first",
				FlagProjectLifecycle:           optionProduction,
				FlagProjectBusinessCriticality: optionCritical,
				FlagProjectEnvironment:         optionBackend,
				FlagReport:                     true,
			},
			hasErr: false,
			desc:   "valid --report options",
		},
		{
			in: map[string]any{
				FlagProjectEnvironment: optionBackend,
				FlagReport:             false,
			},
			hasErr: true,
			desc:   "invalid --project-environment without --report",
		},
		{
			in: map[string]any{
				FlagTargetReference: "main",
				FlagReport:          false,
			},
			hasErr: true,
			desc:   "invalid --target-reference without --report",
		},
		{
			in: map[string]any{
				FlagReport: true,
			},
			hasErr: false,
			desc:   "valid config with only --report",
		},
		{
			in:     map[string]any{},
			hasErr: false,
			desc:   "valid config without --report and no related flags",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)
			err := validateReportConfig(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateFlagsConfig(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in: map[string]any{
				FlagProjectEnvironment: optionBackend,
			},
			hasErr: true,
			desc:   "invalid usage of --project-environment without --report",
		},
		{
			in: map[string]any{
				FlagReport:             true,
				FlagProjectEnvironment: optionBackend,
			},
			hasErr: false,
			desc:   "valid config with valid --report options",
		},
		{
			in: map[string]any{
				FlagSeverityThreshold: "invalid",
			},
			hasErr: true,
			desc:   "invalid --severity-threshold",
		},
		{
			in: map[string]any{
				FlagSeverityThreshold: optionLow,
			},
			hasErr: false,
			desc:   "valid --severity-threshold",
		},
		{
			in: map[string]any{
				FlagTargetReference: "main",
				FlagReport:          false,
			},
			hasErr: true,
			desc:   "invalid --target-reference without --report",
		},
		{
			in: map[string]any{
				FlagTargetReference: "main",
				FlagReport:          true,
			},
			hasErr: false,
			desc:   "valid --target-reference with --report",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateFlagsConfig(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestParseExcludeFlag(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in:     map[string]any{},
			hasErr: false,
			desc:   "no --exclude set, no validation needed",
		},
		{
			in: map[string]any{
				FlagExcludeFilePath: "file.txt",
			},
			hasErr: false,
			desc:   "valid --exclude (single file)",
		},
		{
			in: map[string]any{
				FlagExcludeFilePath: "dir1,file2.txt",
			},
			hasErr: false,
			desc:   "valid --exclude (comma separated list)",
		},
		{
			in: map[string]any{
				FlagExcludeFilePath: "",
			},
			hasErr: true,
			desc:   "invalid empty --exclude",
		},
		{
			in: map[string]any{
				FlagExcludeFilePath: "   ",
			},
			hasErr: true,
			desc:   "invalid whitespace --exclude",
		},
		{
			in: map[string]any{
				FlagExcludeFilePath: "path/to/file",
			},
			hasErr: true,
			desc:   "invalid --exclude with forward slash",
		},
		{
			in: map[string]any{
				FlagExcludeFilePath: `path\to\file`,
			},
			hasErr: true,
			desc:   "invalid --exclude with backward slash",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			_, err := parseExcludeFlag(config)

			if tc.hasErr {
				assert.NotNil(t, err)
				return
			}
			assert.Nil(t, err)
		})
	}
}

func setupMockConfig(flagValues map[string]any) configuration.Configuration {
	config := configuration.New()

	for key, value := range flagValues {
		config.Set(key, value)
	}
	return config
}

func TestValidateRemoteRepoURL(t *testing.T) {
	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in:     map[string]any{},
			hasErr: false,
			desc:   "no --remote-repo-url set, no validation needed",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "",
			},
			hasErr: false,
			desc:   "empty --remote-repo-url is valid",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "https://github.com/snyk/cli-extension-secrets",
			},
			hasErr: false,
			desc:   "valid https URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "http://github.com/snyk/cli-extension-secrets",
			},
			hasErr: false,
			desc:   "valid http URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "git://github.com/snyk/cli-extension-secrets.git",
			},
			hasErr: false,
			desc:   "valid git URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "ssh://git@github.com/snyk/cli-extension-secrets.git",
			},
			hasErr: false,
			desc:   "valid ssh URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "git@github.com:snyk/cli-extension-secrets.git",
			},
			hasErr: false,
			desc:   "valid SCP-style git URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "git@gitlab.com:org/repo.git",
			},
			hasErr: false,
			desc:   "valid SCP-style gitlab URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "user@bitbucket.org:team/project.git",
			},
			hasErr: false,
			desc:   "valid SCP-style bitbucket URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "invalid-url",
			},
			hasErr: true,
			desc:   "invalid URL without scheme or host",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "git+ssh://git@github.com/org/repo.git",
			},
			hasErr: false,
			desc:   "valid git+ssh URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "ssh+git://git@github.com/org/repo.git",
			},
			hasErr: false,
			desc:   "valid ssh+git URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "file:///home/user/repo.git",
			},
			hasErr: false,
			desc:   "valid file URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "https://github.com:8443/org/repo.git",
			},
			hasErr: false,
			desc:   "valid https URL with port",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "ssh://git@github.com:22/org/repo.git",
			},
			hasErr: false,
			desc:   "valid ssh URL with port",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "git@gitlab.com:org/subgroup/repo.git",
			},
			hasErr: false,
			desc:   "valid SCP-style gitlab subgroup URL",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "TOKEN@host:org/repo.git",
			},
			hasErr: false,
			desc:   "valid SCP-style with token user",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "ftp://github.com/snyk/cli-extension-secrets",
			},
			hasErr: true,
			desc:   "invalid URL with unsupported scheme",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "javascript:alert(1)",
			},
			hasErr: true,
			desc:   "invalid URL with javascript scheme",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "-git@github.com:org/repo.git",
			},
			hasErr: true,
			desc:   "invalid SCP URL starting with dash",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: ":path/repo.git",
			},
			hasErr: true,
			desc:   "invalid SCP URL with empty host",
		},
		{
			in: map[string]any{
				FlagRemoteRepoURL: "git@github.com:",
			},
			hasErr: true,
			desc:   "invalid SCP URL with empty path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateRemoteRepoURL(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateStringLengthLimits(t *testing.T) {
	longString := strings.Repeat("a", MaxTargetNameLength+1)

	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in:     map[string]any{},
			hasErr: false,
			desc:   "no flags set, no validation needed",
		},
		{
			in: map[string]any{
				FlagTargetName: "valid-name",
			},
			hasErr: false,
			desc:   "valid --target-name length",
		},
		{
			in: map[string]any{
				FlagTargetName: longString,
			},
			hasErr: true,
			desc:   "invalid --target-name exceeds max length",
		},
		{
			in: map[string]any{
				FlagTargetReference: "main",
			},
			hasErr: false,
			desc:   "valid --target-reference length",
		},
		{
			in: map[string]any{
				FlagTargetReference: longString,
			},
			hasErr: true,
			desc:   "invalid --target-reference exceeds max length",
		},
		{
			in: map[string]any{
				FlagTargetName: strings.Repeat("a", MaxTargetNameLength),
			},
			hasErr: false,
			desc:   "valid --target-name at exactly max length",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateStringLengthLimits(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateFileOutputPaths(t *testing.T) {
	longPath := strings.Repeat("a", MaxFileOutputPathLength+1) + ".json"

	testCases := []struct {
		in     map[string]any
		hasErr bool
		desc   string
	}{
		{
			in:     map[string]any{},
			hasErr: false,
			desc:   "no flags set, no validation needed",
		},
		{
			in: map[string]any{
				FlagJSONFileOutput: "",
			},
			hasErr: false,
			desc:   "empty --json-file-output is valid",
		},
		{
			in: map[string]any{
				FlagJSONFileOutput: "/tmp/output.json",
			},
			hasErr: false,
			desc:   "valid --json-file-output path",
		},
		{
			in: map[string]any{
				FlagSARIFFileOutput: "/tmp/output.sarif",
			},
			hasErr: false,
			desc:   "valid --sarif-file-output path",
		},
		{
			in: map[string]any{
				FlagSARIFFileOutput: "/tmp/output.json",
			},
			hasErr: false,
			desc:   "valid --sarif-file-output with .json extension",
		},
		{
			in: map[string]any{
				FlagJSONFileOutput: longPath,
			},
			hasErr: true,
			desc:   "invalid --json-file-output exceeds max length",
		},
		{
			in: map[string]any{
				FlagJSONFileOutput: "output\x00.json",
			},
			hasErr: true,
			desc:   "invalid --json-file-output with null byte",
		},
		{
			in: map[string]any{
				FlagJSONFileOutput: "./output.json",
			},
			hasErr: false,
			desc:   "valid --json-file-output with relative path",
		},
		{
			in: map[string]any{
				FlagJSONFileOutput: "/nonexistent_dir_12345/output.json",
			},
			hasErr: false,
			desc:   "valid --json-file-output with non-existent parent dir (deferred check)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			config := setupMockConfig(tc.in)

			err := validateFileOutputPaths(config)
			if tc.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}
