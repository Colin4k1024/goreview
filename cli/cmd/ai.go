package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Colin4k1024/goreview/cli/pkg/types"
	"github.com/sashabaranov/go-openai"
)

// AIConfig holds configuration for the AI review
type AIConfig struct {
	Model       string
	APIKey      string
	APIURL      string // For Azure OpenAI (not currently used)
	APIVersion  string // For Azure OpenAI (not currently used)
}

// AIReviewer handles AI-powered code review
type AIReviewer struct {
	client *openai.Client
	config AIConfig
}

// NewAIReviewer creates a new AI reviewer
func NewAIReviewer(config AIConfig) (*AIReviewer, error) {
	client := openai.NewClient(config.APIKey)

	return &AIReviewer{
		client: client,
		config: config,
	}, nil
}

// ReviewFile performs AI review on a single file
func (r *AIReviewer) ReviewFile(filePath string, content []byte) ([]types.Issue, error) {
	if len(content) == 0 {
		return nil, nil
	}

	issueCount := countPotentialIssues(content)
	prompt := buildReviewPrompt(string(content), issueCount)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req := openai.ChatCompletionRequest{
		Model: r.config.Model,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are a Go security and code quality expert. Analyze code for issues and respond ONLY with a JSON array of issues.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		},
		Temperature: 0.1,
	}

	resp, err := r.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AI review failed: %w", err)
	}

	text := strings.TrimSpace(resp.Choices[0].Message.Content)
	if text == "" || text == "null" || text == "[]" {
		return nil, nil
	}

	text = extractJSON(text)

	var issues []types.Issue
	if err := json.Unmarshal([]byte(text), &issues); err != nil {
		if text[0] == '[' {
			fixed := fixJSON(text)
			if err := json.Unmarshal([]byte(fixed), &issues); err != nil {
				return nil, fmt.Errorf("failed to parse AI response: %w", err)
			}
		} else {
			var issue types.Issue
			if err := json.Unmarshal([]byte(text), &issue); err == nil {
				issues = []types.Issue{issue}
			}
		}
	}

	for i := range issues {
		issues[i].Source = "ai"
		issues[i].File = filePath
	}

	return issues, nil
}

func buildReviewPrompt(content string, issueCount int) string {
	return "Analyze this Go code for security vulnerabilities, performance issues, and code quality problems.\n\n" +
		"Focus areas:\n" +
		"1. Security: SQL injection, authentication issues, sensitive data exposure, insecure dependencies\n" +
		"2. Performance: Goroutine leaks, N+1 queries, unnecessary allocations, inefficient algorithms\n" +
		"3. Code Quality: Error handling, concurrency issues, resource management, best practices\n\n" +
		"File content:\n" +
		"```go\n" + content + "\n" +
		"```\n\n" +
		"Respond with a JSON array of issues. Each issue must have:\n" +
		"- severity: \"SEVERE\", \"WARNING\", or \"INFO\"\n" +
		"- title: short description (max 60 chars)\n" +
		"- message: detailed explanation\n" +
		"- line: approximate line number (1-indexed)\n" +
		"- rule_id: one of SQL_INJECTION, SENSITIVE_LOG, GOROUTINE_LEAK, RESOURCE_LEAK, CONTEXT_LEAK, JWT_ERROR, ERROR_SWALLOW, or a custom ID\n" +
		"- suggestion: how to fix it\n\n" +
		"If no issues found, respond with \"[]\".\n\n" +
		fmt.Sprintf("Pre-detected %d potential issues in this file.", issueCount)
}

func extractJSON(text string) string {
	if len(text) == 0 {
		return text
	}

	start := 0
	for i, c := range text {
		if c == '[' || c == '{' {
			start = i
			break
		}
	}

	end := len(text)
	for i := len(text) - 1; i >= start; i-- {
		if text[i] == ']' || text[i] == '}' {
			end = i + 1
			break
		}
	}

	return text[start:end]
}

func fixJSON(s string) string {
	s = strings.ReplaceAll(s, ",\n]", "\n]")
	s = strings.ReplaceAll(s, ",\n}", "\n}")
	s = strings.ReplaceAll(s, ",]", "]")
	s = strings.ReplaceAll(s, ",}", "}")
	return s
}

func countPotentialIssues(content []byte) int {
	count := 0
	text := string(content)

	if strings.Contains(text, "fmt.Sprintf") && strings.Contains(text, "SELECT") {
		count++
	}
	if strings.Contains(text, "go func") {
		count++
	}
	if strings.Contains(text, "password") || strings.Contains(text, "token") {
		count++
	}
	if strings.Contains(text, "sql.Open") || strings.Contains(text, "Query(") {
		count++
	}

	return count
}

func (r *AIReviewer) ReviewFiles(files map[string][]byte, rules []string) ([]types.Issue, error) {
	var allIssues []types.Issue

	for path, content := range files {
		issues, err := r.ReviewFile(path, content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: AI review failed for %s: %v\n", path, err)
			continue
		}

		for _, issue := range issues {
			if len(rules) == 0 {
				allIssues = append(allIssues, issue)
			} else {
				for _, rule := range rules {
					if rule == issue.RuleID || rule == "ALL" {
						allIssues = append(allIssues, issue)
						break
					}
				}
			}
		}
	}

	return allIssues, nil
}
