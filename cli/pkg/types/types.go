package types

import "time"

// Severity represents the severity level of an issue
type Severity string

const (
	SeveritySevere   Severity = "SEVERE"
	SeverityWarning  Severity = "WARNING"
	SeverityInfo     Severity = "INFO"
)

// Issue represents a code issue found during scanning
type Issue struct {
	ID          string   `json:"id" yaml:"id"`
	Severity    Severity `json:"severity" yaml:"severity"`
	Title       string   `json:"title" yaml:"title"`
	Message     string   `json:"message" yaml:"message"`
	File        string   `json:"file" yaml:"file"`
	Line        int      `json:"line" yaml:"line"`
	EndLine     int      `json:"end_line,omitempty" yaml:"end_line,omitempty"`
	Column      int      `json:"column,omitempty" yaml:"column,omitempty"`
	RuleID      string   `json:"rule_id" yaml:"rule_id"`
	Category    string   `json:"category,omitempty" yaml:"category,omitempty"`
	Suggestion  string   `json:"suggestion,omitempty" yaml:"suggestion,omitempty"`
	Source      string   `json:"source,omitempty" yaml:"source,omitempty"` // "static" or "ai"
}

// Result represents the complete scan result
type Result struct {
	TotalFiles  int       `json:"total_files" yaml:"total_files"`
	TotalIssues int       `json:"total_issues" yaml:"total_issues"`
	Severe      int       `json:"severe" yaml:"severe"`
	Warning     int       `json:"warning" yaml:"warning"`
	Info        int       `json:"info" yaml:"info"`
	Duration    string    `json:"duration" yaml:"duration"`
	Timestamp   time.Time `json:"timestamp" yaml:"timestamp"`
	Issues      []Issue   `json:"issues" yaml:"issues"`
	FilesScanned []string `json:"files_scanned,omitempty" yaml:"files_scanned,omitempty"`
}

// Rule represents a static analysis rule
type Rule struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Severity    Severity `json:"severity" yaml:"severity"`
	Category    string   `json:"category" yaml:"category"` // "security", "performance", "best-practice"
	Pattern     string   `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Suggestion  string   `json:"suggestion" yaml:"suggestion"`
}

// FileInfo holds information about a scanned file
type FileInfo struct {
	Path    string
	Content []byte
	Issues  []Issue
}
