package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "0.2.0"

var rootCmd = &cobra.Command{
	Use:   "goreview",
	Short: "GoReview - AI-powered Go code review tool",
	Long: `GoReview is a static analysis and AI-powered code review tool for Go.

Features:
  - Static analysis for common Go issues
  - AI-powered code review using OpenAI
  - Multiple output formats (text, JSON, SARIF)
  - Configurable rules and exclusions

Examples:
  goreview scan ./...
  goreview scan --security --performance
  goreview init  # Create default .goreview.yaml
  goreview version
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'goreview --help' for more information")
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Add version command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number of GoReview",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("GoReview version %s\n", version)
		},
	})

	// Add init command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Create a default .goreview.yaml configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			initConfig()
		},
	})
}

func initConfig() {
	configContent := `# GoReview Configuration
# https://github.com/Colin4k1024/goreview

# AI Model to use (gpt-4o, gpt-4o-mini, etc.)
model: gpt-4o

# API Key (use "env:VARIABLE_NAME" to reference an environment variable)
api_key: env:OPENAI_API_KEY

# Enable/disable rule categories
rules:
  security:
    - SQL_INJECTION
    - SENSITIVE_LOG
    - CONTEXT_LEAK
    - JWT_ERROR
  performance:
    - GOROUTINE_LEAK
    - RESOURCE_LEAK
    - ERROR_SWALLOW

# Files/directories to exclude from scanning
exclude:
  - "**/*_test.go"
  - "**/vendor/**"
  - "**/.git/**"

# Output format: text, json, sarif
output: text

# Azure OpenAI configuration (optional)
# azure_api_url: https://your-resource.openai.azure.com
# azure_api_version: "2024-02-01"

# Skip AI review (run only static analysis)
# no_ai: false
`

	filename := ".goreview.yaml"
	if _, err := os.Stat(filename); err == nil {
		fmt.Printf("Error: %s already exists\n", filename)
		return
	}

	if err := os.WriteFile(filename, []byte(configContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", filename, err)
		return
	}

	fmt.Printf("Created %s\n", filename)
}
