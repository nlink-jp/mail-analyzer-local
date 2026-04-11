// Package config provides configuration for mail-analyzer-local.
package config

import (
	"fmt"
	"os"
)

// Config holds runtime configuration.
type Config struct {
	Endpoint string // OpenAI-compatible API endpoint
	Model    string // Model name
	APIKey   string // API key (optional)
	Lang     string // Force summary language (optional)
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	c := &Config{
		Endpoint: os.Getenv("MAIL_ANALYZER_LOCAL_ENDPOINT"),
		Model:    os.Getenv("MAIL_ANALYZER_LOCAL_MODEL"),
		APIKey:   os.Getenv("MAIL_ANALYZER_LOCAL_API_KEY"),
		Lang:     os.Getenv("MAIL_ANALYZER_LOCAL_LANG"),
	}

	if c.Endpoint == "" {
		return nil, fmt.Errorf("MAIL_ANALYZER_LOCAL_ENDPOINT is required")
	}
	if c.Model == "" {
		return nil, fmt.Errorf("MAIL_ANALYZER_LOCAL_MODEL is required")
	}

	return c, nil
}
