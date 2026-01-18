package cli

import (
	"LogZero/app"
)

// ConfigToAppConfig converts a CLI Config to an app.Config
func ConfigToAppConfig(cliConfig *Config) *app.Config {
	return &app.Config{
		InputPath:      cliConfig.InputPath,
		OutputPath:     cliConfig.OutputPath,
		Format:         cliConfig.Format,
		Workers:        cliConfig.Workers,
		BufferSize:     cliConfig.BufferSize,
		FilterPattern:  cliConfig.FilterPattern,
		Verbose:        cliConfig.Verbose,
		Silent:         cliConfig.Silent,
		JSONStatus:     cliConfig.JSONStatus,
	}
}