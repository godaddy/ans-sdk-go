package config

import (
	"github.com/spf13/viper"
)

// Config represents application configuration
type Config struct {
	BaseURL string
	APIKey  string //nolint:gosec // G117 - config struct field definition, not logged
	Verbose bool
	JSON    bool
}

// Load loads configuration from environment and flags
func Load() (*Config, error) {
	cfg := &Config{
		BaseURL: viper.GetString("base-url"),
		APIKey:  viper.GetString("api-key"),
		Verbose: viper.GetBool("verbose"),
		JSON:    viper.GetBool("json"),
	}

	return cfg, nil
}
