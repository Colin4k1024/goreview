package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sashabaranov/go-openai"
)

const version = "0.1.0"

var (
	flagSecurity   = flag.Bool("security", true, "Enable security checks")
	flagPerf       = flag.Bool("performance", false, "Enable performance checks")
	flagOutputJSON = flag.Bool("json", false, "Output JSON format")
	flagModel      = flag.String("model", "gpt-4o", "OpenAI model to use")
)

type Issue struct {
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	RuleID    string `json:"rule_id"`
	Suggestion string `json:"suggestion,omitempty"`
}

type Result struct {
	TotalFiles  int     `json:"total_files"`
	TotalIssues int     `json:"total_issues"`
	Severe      int     `json:"severe"`
	Warning     int     `json:"warning"`
	Duration    string  `json:"duration"`
	Issues      []Issue `json:"issues"`
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		args = []string{"./..."}
	}

	token := os.Getenv("OPENAI_API_KEY")
	if token == "" {
		fmt.Fprintf(os.Stderr, "Error: OPENAI_API_KEY not set\n")
		os.Exit(1)
	}

	start := time.Now()

	// Find all .go files
	var files []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "github.com/") || strings.HasPrefix(arg, "github.com") {
			// Skip remote repos for now
			continue
		}
		filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(path, ".go") {
				files = append(files, path)
			}
			return nil
		})
	}

	fmt.Printf("# Scanning %d Go files...\n\n", len(files))

	var (
		issues []Issue
		mu     sync.Mutex
		wg     sync.WaitGroup
		sem    = make(chan struct{}, 5) // concurrency limit
	)

	client := openai.NewClient(token)

	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fileIssues := scanFile(client, file)
			if len(fileIssues) > 0 {
				mu.Lock()
				issues = append(issues, fileIssues...)
				mu.Unlock()
			}
		}(file)
	}

	wg.Wait()

	severe := 0
	warn := 0
	for _, i := range issues {
		if i.Severity == "SEVERE" {
			severe++
		} else {
			warn++
		}
	}

	duration := time.Since(start)
	result := Result{
		TotalFiles:  len(files),
		TotalIssues: len(issues),
		Severe:      severe,
		Warning:     warn,
		Duration:    duration.String(),
		Issues:      issues,
	}

	if *flagOutputJSON {
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
		return
	}

	// Text output
	for _, issue := range issues {
		icon := "⚠ WARN"
		if issue.Severity == "SEVERE" {
			icon = "✗ SEVERE"
		}
		fmt.Printf("%s  %s\n", icon, issue.Title)
		fmt.Printf("   → %s:%d\n", issue.File, issue.Line)
		if issue.Suggestion != "" {
			fmt.Printf("   💡 %s\n", issue.Suggestion)
		}
		fmt.Println()
	}

	fmt.Printf("%d issues found (%d severe, %d warning)\n", len(issues), severe, warn)
	fmt.Printf("Done in %s\n", duration)
}

func scanFile(client *openai.Client, file string) []Issue {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	if len(content) == 0 {
		return nil
	}

	prompt := fmt.Sprintf(`You are a Go security expert. Review this Go code for security and performance issues.

Focus on these specific patterns:

SECURITY:
1. Context leaks: goroutine uses context after it's been cancelled (ctx passed to goroutine after defer cancel())
2. SQL injection: string concatenation/formatting in SQL queries (fmt.Sprintf, strings.Join for SQL)
3. JWT validation errors: verifying signature but not expiration, trusting X-User-ID header directly
4. Sensitive data in error logs: logging tokens, passwords, emails in error messages
5. Resource leaks: database/sql, io.Closer, redis connections not properly closed

PERFORMANCE:
1. Goroutine leaks: goroutines started without stop channels or wait groups
2. N+1 query patterns
3. Unnecessary allocations

Respond ONLY with a JSON array of issues found. Each issue must have these exact fields:
- severity: "SEVERE" or "WARNING"
- title: short description
- message: explanation
- file: the filename
- line: approximate line number (1-indexed)
- rule_id: one of: CONTEXT_LEAK, SQL_INJECTION, JWT_ERROR, SENSITIVE_LOG, GOROUTINE_LEAK, RESOURCE_LEAK
- suggestion: how to fix it

If no issues found, respond with "[]".

Code to review:
\`\`\`go
%s
\`\`\`
`, string(content))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: *flagModel,
		Messages: []openai.ChatMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are a Go security expert. Be precise and helpful.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
		ResponseFormat: "json_object",
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", file, err)
		return nil
	}

	text := strings.TrimSpace(resp.Choices[0].Message.Content)
	
	// Handle empty or null responses
	text = strings.TrimSpace(text)
	if text == "" || text == "null" || text == "[]" {
		return nil
	}

	// Try to extract JSON from response if it has extra text
	if text[0] != '[' && text[0] != '{' {
		// Find JSON start
		start := strings.Index(text, "[")
		if start == -1 {
			start = strings.Index(text, "{")
		}
		if start > 0 {
			text = text[start:]
		}
	}

	var issues []Issue
	if text[0] == '[' {
		if err := json.Unmarshal([]byte(text), &issues); err != nil {
			// Try to fix common JSON issues
			text = fixJSON(text)
			if err := json.Unmarshal([]byte(text), &issues); err != nil {
				fmt.Fprintf(os.Stderr, "Parse error for %s: %v\n", file, err)
				return nil
			}
		}
	} else {
		// Single object
		var issue Issue
		if err := json.Unmarshal([]byte(text), &issue); err == nil {
			issues = []Issue{issue}
		}
	}

	// Filter by enabled checks
	var filtered []Issue
	for _, issue := range issues {
		if strings.HasPrefix(issue.RuleID, "SQL_") || strings.HasPrefix(issue.RuleID, "JWT_") ||
			strings.HasPrefix(issue.RuleID, "CONTEXT_") || strings.HasPrefix(issue.RuleID, "SENSITIVE_") {
			if *flagSecurity {
				filtered = append(filtered, issue)
			}
		} else if strings.HasPrefix(issue.RuleID, "GOROUTINE_") || strings.HasPrefix(issue.RuleID, "RESOURCE_") {
			if *flagPerf {
				filtered = append(filtered, issue)
			}
		}
	}

	return filtered
}

func fixJSON(s string) string {
	// Remove trailing commas before ]
	s = strings.ReplaceAll(s, ",]", "]")
	// Remove trailing commas before }
	s = strings.ReplaceAll(s, ",}", "}")
	return s
}
