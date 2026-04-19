package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Colin4k1024/goreview/cli/pkg/analyzer"
	"github.com/Colin4k1024/goreview/cli/pkg/config"
	"github.com/Colin4k1024/goreview/cli/pkg/output"
	"github.com/Colin4k1024/goreview/cli/pkg/types"
	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan Go files for issues",
	Long: `Scan Go files for security vulnerabilities, performance issues, 
and code quality problems using static analysis and AI-powered review.

Examples:
  goreview scan ./...
  goreview scan --security --performance
  goreview scan --no-ai --output json
  goreview scan --rules SQL_INJECTION,GOROUTINE_LEAK
  goreview scan --config .goreview.yaml
`,
	RunE: runScan,
}

var (
	flagSecurity    bool
	flagPerformance bool
	flagNoAI        bool
	flagOutput      string
	flagModel       string
	flagRules       string
	flagConfig      string
	flagJSON        bool
)

func init() {
	scanCmd.Flags().BoolVar(&flagSecurity, "security", true, "Enable security checks")
	scanCmd.Flags().BoolVar(&flagPerformance, "performance", false, "Enable performance checks")
	scanCmd.Flags().BoolVar(&flagNoAI, "no-ai", false, "Disable AI-powered review")
	scanCmd.Flags().BoolVar(&flagJSON, "json", false, "Output JSON format (shorthand for --output json)")
	scanCmd.Flags().StringVar(&flagOutput, "output", "text", "Output format: text, json, sarif")
	scanCmd.Flags().StringVar(&flagModel, "model", "gpt-4o", "AI model to use (gpt-4o, gpt-4o-mini, etc.)")
	scanCmd.Flags().StringVar(&flagRules, "rules", "", "Comma-separated list of rules to enable (default: all)")
	scanCmd.Flags().StringVar(&flagConfig, "config", "", "Config file path (default: .goreview.yaml)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	start := time.Now()

	// Determine paths to scan
	var paths []string
	if len(args) == 0 {
		paths = []string{"."}
	} else {
		paths = args
	}

	// Load configuration
	cfg, err := loadConfiguration()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override config with command line flags
	if flagJSON {
		cfg.Output = "json"
	}
	if flagOutput != "text" {
		cfg.Output = flagOutput
	}
	if flagNoAI {
		cfg.NoAI = true
	}
	if flagModel != "gpt-4o" {
		cfg.Model = flagModel
	}

	// Determine which rules to enable
	enabledRules := determineEnabledRules(cfg)

	// Find all Go files
	files, err := findGoFiles(paths, cfg)
	if err != nil {
		return fmt.Errorf("failed to find Go files: %w", err)
	}

	if len(files) == 0 {
		fmt.Println("No Go files found to scan")
		return nil
	}

	fmt.Printf("Scanning %d Go files...\n\n", len(files))

	// Run static analysis
	staticIssues := runStaticAnalysis(files, enabledRules)

	// Run AI review if enabled
	var aiIssues []types.Issue
	if !cfg.NoAI && cfg.GetAPIKey() != "" {
		aiIssues = runAIReview(files, cfg)
	}

	// Combine and deduplicate issues
	allIssues := combineIssues(staticIssues, aiIssues)

	// Count issues by severity
	severe := 0
	warning := 0
	info := 0
	for _, issue := range allIssues {
		switch issue.Severity {
		case types.SeveritySevere:
			severe++
		case types.SeverityWarning:
			warning++
		case types.SeverityInfo:
			info++
		}
	}

	duration := time.Since(start)
	result := &types.Result{
		TotalFiles:   len(files),
		TotalIssues:  len(allIssues),
		Severe:       severe,
		Warning:      warning,
		Info:         info,
		Duration:     duration.String(),
		Timestamp:    time.Now(),
		Issues:       allIssues,
		FilesScanned: files,
	}

	// Output results
	formatter := output.GetFormatter(cfg.Output)
	outputBytes, err := formatter.Format(result)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	fmt.Print(string(outputBytes))

	// Return error code if severe issues found
	if severe > 0 {
		os.Exit(1)
	}

	return nil
}

func loadConfiguration() (*config.Config, error) {
	var cfg *config.Config
	var err error

	if flagConfig != "" {
		cfg, err = config.Load(flagConfig)
	} else {
		cfg, err = config.LoadDefault()
	}

	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func determineEnabledRules(cfg *config.Config) []types.Rule {
	var enabled []types.Rule

	// Parse rules flag
	specifiedRules := make(map[string]bool)
	if flagRules != "" {
		for _, r := range strings.Split(flagRules, ",") {
			specifiedRules[strings.TrimSpace(r)] = true
		}
	}

	for _, rule := range AllRules {
		if rule.Category == "ai" {
			continue // AI rules are handled separately
		}

		// If specific rules were requested, only enable those
		if len(specifiedRules) > 0 {
			if specifiedRules[rule.ID] || specifiedRules["ALL"] {
				enabled = append(enabled, rule)
			}
			continue
		}

		// Otherwise use config and category flags
		if rule.Category == "security" && (flagSecurity || cfg.Rules.All) {
			if cfg.IsRuleEnabled(rule.ID) {
				enabled = append(enabled, rule)
			}
		}
		if rule.Category == "performance" && (flagPerformance || cfg.Rules.All) {
			if cfg.IsRuleEnabled(rule.ID) {
				enabled = append(enabled, rule)
			}
		}
		if rule.Category == "best-practice" && (flagSecurity || flagPerformance || cfg.Rules.All) {
			if cfg.IsRuleEnabled(rule.ID) {
				enabled = append(enabled, rule)
			}
		}
	}

	return enabled
}

func findGoFiles(paths []string, cfg *config.Config) ([]string, error) {
	var files []string

	for _, path := range paths {
		err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Skip directories
			if info.IsDir() {
				// Skip vendor directories
				if info.Name() == "vendor" || info.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}

			// Only process .go files
			if !strings.HasSuffix(filePath, ".go") {
				return nil
			}

			// Check exclusions
			if cfg.ShouldExclude(filePath) {
				return nil
			}

			files = append(files, filePath)
			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	return files, nil
}

func runStaticAnalysis(files []string, rules []types.Rule) []types.Issue {
	analyzerInstance := analyzer.New(rules)
	var allIssues []types.Issue
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrency
	sem := make(chan struct{}, 5)

	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			content, err := os.ReadFile(file)
			if err != nil {
				return
			}

			issues, err := analyzerInstance.AnalyzeFile(file, content)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Static analysis error for %s: %v\n", file, err)
				return
			}

			if len(issues) > 0 {
				mu.Lock()
				allIssues = append(allIssues, issues...)
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait()
	return allIssues
}

func runAIReview(files []string, cfg *config.Config) []types.Issue {
	aiConfig := AIConfig{
		Model:       cfg.Model,
		APIKey:      cfg.GetAPIKey(),
		APIURL:     cfg.AzureAPIURL,
		APIVersion: cfg.AzureAPIVersion,
	}

	reviewer, err := NewAIReviewer(aiConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize AI reviewer: %v\n", err)
		return nil
	}

	// Read all file contents
	fileContents := make(map[string][]byte)
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		fileContents[file] = content
	}

	var rules []string
	if len(cfg.Rules.Security) > 0 {
		rules = cfg.Rules.Security
	}

	issues, err := reviewer.ReviewFiles(fileContents, rules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "AI review error: %v\n", err)
		return nil
	}

	return issues
}

func combineIssues(static, ai []types.Issue) []types.Issue {
	// Simple deduplication based on file, line, and rule ID
	seen := make(map[string]bool)
	var combined []types.Issue

	// Add static issues first (they're more reliable)
	for _, issue := range static {
		key := fmt.Sprintf("%s:%d:%s", issue.File, issue.Line, issue.RuleID)
		if !seen[key] {
			seen[key] = true
			combined = append(combined, issue)
		}
	}

	// Add AI issues (skip duplicates)
	for _, issue := range ai {
		key := fmt.Sprintf("%s:%d:%s", issue.File, issue.Line, issue.RuleID)
		if !seen[key] {
			seen[key] = true
			combined = append(combined, issue)
		}
	}

	return combined
}
