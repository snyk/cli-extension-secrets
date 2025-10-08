package secretstest

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

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
					FlagProjectEnvironment: "backend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
				},
			},
			hasErr: false,
			desc:   "valid flag",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "backend,backend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
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
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
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
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
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
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
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
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
					allowEmpty:   true,
				},
			},
			hasErr: true,
			desc:   "invalid flag format",
		},
		{
			in: testInput{
				config: map[string]any{
					FlagProjectEnvironment: "backend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
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
					FlagProjectEnvironment: "backend,frontend",
				},
				flag: flagWithOptions{
					name:         FlagProjectEnvironment,
					validOptions: map[string]struct{}{"backend": {}, "frontend": {}},
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
				FlagProjectLifecycle:           "production",
				FlagProjectBusinessCriticality: "critical",
				FlagProjectEnvironment:         "backend",
				FlagReport:                     true,
			},
			hasErr: false,
			desc:   "valid --report options",
		},
		{
			in: map[string]any{
				FlagProjectEnvironment: "backend",
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
				FlagProjectEnvironment: "backend",
			},
			hasErr: true,
			desc:   "invalid usage of --project-environment without --report",
		},
		{
			in: map[string]any{
				FlagReport:             true,
				FlagProjectEnvironment: "backend",
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
				FlagSeverityThreshold: "low",
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

func setupMockConfig(flagValues map[string]any) configuration.Configuration {
	config := configuration.New()

	for key, value := range flagValues {
		config.Set(key, value)
	}
	return config
}
