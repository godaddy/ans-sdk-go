package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		setup       func()
		wantBaseURL string
		wantAPIKey  string
		wantVerbose bool
		wantJSON    bool
	}{
		{
			name: "default values",
			setup: func() {
				viper.Reset()
			},
			wantBaseURL: "",
			wantAPIKey:  "",
			wantVerbose: false,
			wantJSON:    false,
		},
		{
			name: "with all values set",
			setup: func() {
				viper.Reset()
				viper.Set("base-url", "https://api.example.com")
				viper.Set("api-key", "test-key:test-secret")
				viper.Set("verbose", true)
				viper.Set("json", true)
			},
			wantBaseURL: "https://api.example.com",
			wantAPIKey:  "test-key:test-secret",
			wantVerbose: true,
			wantJSON:    true,
		},
		{
			name: "with partial values",
			setup: func() {
				viper.Reset()
				viper.Set("base-url", "https://api.test.com")
				viper.Set("verbose", true)
			},
			wantBaseURL: "https://api.test.com",
			wantAPIKey:  "",
			wantVerbose: true,
			wantJSON:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("Load() returned nil config")
			}

			if cfg.BaseURL != tt.wantBaseURL {
				t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, tt.wantBaseURL)
			}
			if cfg.APIKey != tt.wantAPIKey {
				t.Errorf("APIKey = %q, want %q", cfg.APIKey, tt.wantAPIKey)
			}
			if cfg.Verbose != tt.wantVerbose {
				t.Errorf("Verbose = %v, want %v", cfg.Verbose, tt.wantVerbose)
			}
			if cfg.JSON != tt.wantJSON {
				t.Errorf("JSON = %v, want %v", cfg.JSON, tt.wantJSON)
			}
		})
	}
}
