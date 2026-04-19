package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the .goreview.yaml configuration
type Config struct {
	Model   string      `yaml:"model"`
	APIKey  string      `yaml:"api_key"`
	Rules   RulesConfig `yaml:"rules"`
	Exclude []string    `yaml:"exclude"`
	Output  string      `yaml:"output"`

	// Azure OpenAI specific
	AzureAPIURL     string `yaml:"azure_api_url,omitempty"`
	AzureAPIVersion string `yaml:"azure_api_version,omitempty"`

	// Additional options
	NoAI       bool `yaml:"no_ai,omitempty"`
	Confidence int  `yaml:"confidence,omitempty"` // 0-100
}

// RulesConfig holds rule configurations
type RulesConfig struct {
	Security    []string `yaml:"security,omitempty"`
	Performance []string `yaml:"performance,omitempty"`
	All         bool     `yaml:"all,omitempty"`
}

// Load loads configuration from a file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Handle api_key with env: prefix
	if strings.HasPrefix(cfg.APIKey, "env:") {
		envKey := strings.TrimPrefix(cfg.APIKey, "env:")
		cfg.APIKey = os.Getenv(envKey)
	}

	// Set defaults
	if cfg.Model == "" {
		cfg.Model = "gpt-4o"
	}
	if cfg.Output == "" {
		cfg.Output = "text"
	}
	if cfg.Confidence == 0 {
		cfg.Confidence = 70
	}

	return &cfg, nil
}

// LoadDefault loads the default .goreview.yaml from current directory
func LoadDefault() (*Config, error) {
	paths := []string{
		".goreview.yaml",
		".goreview.yml",
		"goreview.yaml",
		"goreview.yml",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return Load(path)
		}
	}

	// Return default config if no file found
	return &Config{
		Model:   "gpt-4o",
		Output:  "text",
		Exclude: []string{"**/*_test.go", "**/vendor/**"},
		Rules: RulesConfig{
			All: true,
		},
	}, nil
}

// GetAPIKey returns the API key, checking environment if needed
func (c *Config) GetAPIKey() string {
	if c.APIKey != "" {
		return c.APIKey
	}
	return os.Getenv("OPENAI_API_KEY")
}

// IsRuleEnabled checks if a rule is enabled in the config
func (c *Config) IsRuleEnabled(ruleID string) bool {
	if c.Rules.All {
		return true
	}

	// Check security rules
	for _, r := range c.Rules.Security {
		if r == ruleID || r == "ALL" {
			return true
		}
	}

	// Check performance rules
	for _, r := range c.Rules.Performance {
		if r == ruleID || r == "ALL" {
			return true
		}
	}

	return false
}

// ShouldExclude checks if a path should be excluded
func (c *Config) ShouldExclude(path string) bool {
	for _, pattern := range c.Exclude {
		if match, _ := filepath.Match(pattern, path); match {
			return true
		}
		// Simple glob matching for ** patterns
		if strings.Contains(pattern, "**") {
			cleanPattern := strings.ReplaceAll(pattern, "**", "*")
			if match, _ := filepath.Match(cleanPattern, path); match {
				return true
			}
		}
	}
	return false
}
