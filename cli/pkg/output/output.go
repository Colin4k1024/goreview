package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Colin4k1024/goreview/cli/pkg/types"
)

// Formatter defines an interface for outputting results
type Formatter interface {
	Format(result *types.Result) ([]byte, error)
	Name() string
}

// TextFormatter outputs results in human-readable text format
type TextFormatter struct {
	Color bool
}

// JSONFormatter outputs results in JSON format
type JSONFormatter struct {
	Pretty bool
}

// SARIFFormatter outputs results in SARIF format for GitHub code scanning
type SARIFFormatter struct{}

// TextFormatter implementation
func (f *TextFormatter) Name() string {
	return "text"
}

func (f *TextFormatter) Format(result *types.Result) ([]byte, error) {
	var builder strings.Builder

	// Header
	builder.WriteString(fmt.Sprintf("\n🔍 GoReview Scan Results\n"))
	builder.WriteString(fmt.Sprintf("========================\n\n"))
	builder.WriteString(fmt.Sprintf("Files scanned: %d\n", result.TotalFiles))
	builder.WriteString(fmt.Sprintf("Issues found: %d (", result.TotalIssues))
	
	// Color-coded summary
	if result.Severe > 0 {
		if f.Color {
			builder.WriteString(fmt.Sprintf("\033[1;31m%d severe\033[0m, ", result.Severe))
		} else {
			builder.WriteString(fmt.Sprintf("%d severe, ", result.Severe))
		}
	}
	if result.Warning > 0 {
		if f.Color {
			builder.WriteString(fmt.Sprintf("\033[1;33m%d warning\033[0m", result.Warning))
		} else {
			builder.WriteString(fmt.Sprintf("%d warning", result.Warning))
		}
	}
	if result.Info > 0 {
		if f.Color {
			builder.WriteString(fmt.Sprintf(", \033[1;34m%d info\033[0m", result.Info))
		} else {
			builder.WriteString(fmt.Sprintf(", %d info", result.Info))
		}
	}
	builder.WriteString(fmt.Sprintf(")\n"))
	builder.WriteString(fmt.Sprintf("Duration: %s\n\n", result.Duration))

	// Issues grouped by file
	currentFile := ""
	for _, issue := range result.Issues {
		if issue.File != currentFile {
			currentFile = issue.File
			builder.WriteString(fmt.Sprintf("\n📄 %s\n", currentFile))
			builder.WriteString(strings.Repeat("─", len(currentFile)+4) + "\n")
		}

		// Issue icon and severity
		icon := "⚠"
		severityColor := ""
		severityText := "WARNING"
		
		switch issue.Severity {
		case types.SeveritySevere:
			icon = "✗"
			severityText = "SEVERE"
			if f.Color {
				severityColor = "\033[1;31m"
			}
		case types.SeverityWarning:
			icon = "⚠"
			severityText = "WARNING"
			if f.Color {
				severityColor = "\033[1;33m"
			}
		case types.SeverityInfo:
			icon = "ℹ"
			severityText = "INFO"
			if f.Color {
				severityColor = "\033[1;34m"
			}
		}

		reset := ""
		if f.Color {
			reset = "\033[0m"
		}

		source := ""
		if issue.Source != "" {
			source = fmt.Sprintf(" [%s]", issue.Source)
		}

		builder.WriteString(fmt.Sprintf("  %s %s%s%s%s  %s\n",
			icon, severityColor, severityText, reset, source, issue.Title))
		builder.WriteString(fmt.Sprintf("     → %s:%d\n", issue.File, issue.Line))
		if issue.Suggestion != "" {
			builder.WriteString(fmt.Sprintf("     💡 %s\n", issue.Suggestion))
		}
	}

	if result.TotalIssues == 0 {
		builder.WriteString("\n✅ No issues found!\n")
	}

	return []byte(builder.String()), nil
}

// JSONFormatter implementation
func (f *JSONFormatter) Name() string {
	return "json"
}

func (f *JSONFormatter) Format(result *types.Result) ([]byte, error) {
	if f.Pretty {
		return json.MarshalIndent(result, "", "  ")
	}
	return json.Marshal(result)
}

// SARIFFormatter implementation
func (f *SARIFFormatter) Name() string {
	return "sarif"
}

func (f *SARIFFormatter) Format(result *types.Result) ([]byte, error) {
	// Build SARIF 2.1.0 output
	sarif := SARIFOutput{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            "GoReview",
						Version:         "0.2.0",
						SemanticVersion: "0.2.0",
						Rules:           buildSARIFRules(result.Issues),
					},
				},
				Results: buildSARIFResults(result.Issues),
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// SARIF structures
type SARIFOutput struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool   `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription string `json:"shortDescription,omitempty"`
	DefaultLevel     string `json:"defaultLevel"`
	HelpText         string `json:"helpText,omitempty"`
}

type SARIFResult struct {
	RuleID    string        `json:"ruleId"`
	RuleIndex int           `json:"ruleIndex"`
	Level     string        `json:"level"`
	Message   SARIFMessage  `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

func buildSARIFRules(issues []types.Issue) []SARIFRule {
	ruleMap := make(map[string]bool)
	var rules []SARIFRule

	ruleIDs := make(map[string]string)
	ruleIDs["SQL_INJECTION"] = "SQL Injection"
	ruleIDs["SENSITIVE_LOG"] = "Sensitive Data Logging"
	ruleIDs["GOROUTINE_LEAK"] = "Potential Goroutine Leak"
	ruleIDs["RESOURCE_LEAK"] = "Resource Leak"
	ruleIDs["CONTEXT_LEAK"] = "Context Leak"
	ruleIDs["ERROR_SWALLOW"] = "Swallowed Error"
	ruleIDs["AI_REVIEW"] = "AI-Powered Review Finding"

	for _, issue := range issues {
		if !ruleMap[issue.RuleID] {
			ruleMap[issue.RuleID] = true
			name := ruleIDs[issue.RuleID]
			if name == "" {
				name = issue.RuleID
			}
			level := "warning"
			if issue.Severity == types.SeveritySevere {
				level = "error"
			}
			rules = append(rules, SARIFRule{
				ID:               issue.RuleID,
				Name:             name,
				ShortDescription: issue.Title,
				DefaultLevel:     level,
				HelpText:         issue.Suggestion,
			})
		}
	}
	return rules
}

func buildSARIFResults(issues []types.Issue) []SARIFResult {
	results := make([]SARIFResult, 0, len(issues))
	for i, issue := range issues {
		level := "warning"
		if issue.Severity == types.SeveritySevere {
			level = "error"
		} else if issue.Severity == types.SeverityInfo {
			level = "note"
		}

		region := Region{StartLine: issue.Line}
		if issue.EndLine > 0 {
			region.EndLine = issue.EndLine
		}
		if issue.Column > 0 {
			region.StartColumn = issue.Column
		}

		results = append(results, SARIFResult{
			RuleID:    issue.RuleID,
			RuleIndex: i,
			Level:     level,
			Message:   SARIFMessage{Text: issue.Message},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{URI: issue.File},
						Region:           region,
					},
				},
			},
		})
	}
	return results
}

// GetFormatter returns the appropriate formatter by name
func GetFormatter(name string) Formatter {
	switch strings.ToLower(name) {
	case "json":
		return &JSONFormatter{Pretty: true}
	case "sarif":
		return &SARIFFormatter{}
	default:
		return &TextFormatter{Color: true}
	}
}
