package cmd

import (
	"github.com/Colin4k1024/goreview/cli/pkg/types"
)

// AllRules contains all available static analysis rules
var AllRules = []types.Rule{
	// Security Rules
	{
		ID:          "SQL_INJECTION",
		Name:        "SQL Injection",
		Description: "Detects potential SQL injection vulnerabilities",
		Severity:    types.SeveritySevere,
		Category:    "security",
		Suggestion:  "Use parameterized queries instead of string formatting for SQL queries",
	},
	{
		ID:          "SENSITIVE_LOG",
		Name:        "Sensitive Data Logging",
		Description: "Detects logging of sensitive data like passwords, tokens, API keys",
		Severity:    types.SeveritySevere,
		Category:    "security",
		Suggestion:  "Remove sensitive fields from log statements",
	},
	{
		ID:          "CONTEXT_LEAK",
		Name:        "Context Leak",
		Description: "Detects context being passed to goroutines after cancellation",
		Severity:    types.SeveritySevere,
		Category:    "security",
		Suggestion:  "Use a copy of context or pass context with timeout to goroutines",
	},
	{
		ID:          "JWT_ERROR",
		Name:        "JWT Validation Error",
		Description: "Detects improper JWT token validation",
		Severity:    types.SeveritySevere,
		Category:    "security",
		Suggestion:  "Always verify JWT signature, expiration, and issuer claims",
	},

	// Performance Rules
	{
		ID:          "GOROUTINE_LEAK",
		Name:        "Goroutine Leak",
		Description: "Detects goroutines started without proper lifecycle management",
		Severity:    types.SeverityWarning,
		Category:    "performance",
		Suggestion:  "Use errgroup or context to manage goroutine lifecycle",
	},
	{
		ID:          "RESOURCE_LEAK",
		Name:        "Resource Leak",
		Description: "Detects unclosed resources like database connections, files, etc.",
		Severity:    types.SeverityWarning,
		Category:    "performance",
		Suggestion:  "Ensure resources are properly closed with defer or in finally blocks",
	},
	{
		ID:          "ERROR_SWALLOW",
		Name:        "Error Swallowing",
		Description: "Detects errors that are silently discarded",
		Severity:    types.SeverityWarning,
		Category:    "best-practice",
		Suggestion:  "Handle all errors appropriately, don't ignore them silently",
	},

	// AI Review placeholder
	{
		ID:          "AI_REVIEW",
		Name:        "AI Review Finding",
		Description: "Issue found by AI-powered code review",
		Severity:    types.SeverityWarning,
		Category:    "ai",
		Suggestion:  "Review and fix the issue as suggested",
	},
}

// GetRuleByID returns a rule by its ID
func GetRuleByID(id string) *types.Rule {
	for i := range AllRules {
		if AllRules[i].ID == id {
			return &AllRules[i]
		}
	}
	return nil
}

// GetRulesByCategory returns all rules in a specific category
func GetRulesByCategory(category string) []types.Rule {
	var rules []types.Rule
	for _, rule := range AllRules {
		if rule.Category == category {
			rules = append(rules, rule)
		}
	}
	return rules
}

// GetSecurityRules returns all security rules
func GetSecurityRules() []types.Rule {
	return GetRulesByCategory("security")
}

// GetPerformanceRules returns all performance rules
func GetPerformanceRules() []types.Rule {
	return GetRulesByCategory("performance")
}
