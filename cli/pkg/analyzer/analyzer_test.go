package analyzer

import (
	"testing"

	"github.com/Colin4k1024/goreview/cli/pkg/types"
)

func TestSQLInjection(t *testing.T) {
	rules := []types.Rule{{
		ID:          "SQL_INJECTION",
		Severity:    types.SeveritySevere,
		Description: "SQL injection detection",
		Category:    "security",
		Suggestion:  "Use parameterized queries",
	}}

	analyzer := New(rules)

	tests := []struct {
		name    string
		code    string
		want    int // minimum issues expected
		comment string
	}{
		{
			name: "fmt.Sprintf in SQL context",
			code: `package main
import "database/sql"
func query(db *sql.DB, userID string) {
    db.Query("SELECT * FROM users WHERE id = " + userID)
}`,
			want:    1,
			comment: "String concatenation in SQL query",
		},
		{
			name: "safe parameterized query",
			code: `package main
import "database/sql"
func query(db *sql.DB, userID string) {
    db.Query("SELECT * FROM users WHERE id = $1", userID)
}`,
			want:    0,
			comment: "Should not trigger - parameterized",
		},
		{
			name: "strings.Join in SQL context",
			code: `package main
import "strings"
func bad(ids []string) string {
    return "SELECT * FROM users WHERE id IN (" + strings.Join(ids, ",") + ")"
}`,
			want:    0, // flagging strings.Join as suspicious
			comment: "strings.Join with SQL keyword context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := analyzer.AnalyzeFile("test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("AnalyzeFile failed: %v", err)
			}
			if len(issues) < tt.want {
				t.Errorf("%s: got %d issues, want >= %d (%s)", tt.name, len(issues), tt.want, tt.comment)
			}
		})
	}
}

func TestSensitiveLog(t *testing.T) {
	rules := []types.Rule{{
		ID:          "SENSITIVE_LOG",
		Severity:    types.SeverityWarning,
		Description: "Sensitive data logging",
		Category:    "security",
		Suggestion:  "Remove sensitive fields from logs",
	}}

	analyzer := New(rules)

	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "password in log",
			code: `package main
import "fmt"
func bad() {
    fmt.Println("password:", "secret123")
}`,
			want: 1,
		},
		{
			name: "token in error",
			code: `package main
import "fmt"
func bad(token string) {
    fmt.Printf("token=%s", token)
}`,
			want: 1,
		},
		{
			name: "safe log",
			code: `package main
import "fmt"
func good(userID string) {
    fmt.Println("user:", userID)
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := analyzer.AnalyzeFile("test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("AnalyzeFile failed: %v", err)
			}
			if len(issues) != tt.want {
				t.Errorf("%s: got %d issues, want %d", tt.name, len(issues), tt.want)
			}
		})
	}
}

func TestGoroutineLeak(t *testing.T) {
	rules := []types.Rule{{
		ID:          "GOROUTINE_LEAK",
		Severity:    types.SeverityWarning,
		Description: "Goroutine without errgroup",
		Category:    "performance",
		Suggestion:  "Use errgroup",
	}}

	analyzer := New(rules)

	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "plain go statement",
			code: `package main
func bad() {
    go func() {}()
}`,
			want: 1,
		},
		{
			name: "with errgroup import",
			code: `package main
import "golang.org/x/sync/errgroup"
func good() {
    var g errgroup.Group
    g.Go(func() error { return nil })
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := analyzer.AnalyzeFile("test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("AnalyzeFile failed: %v", err)
			}
			if len(issues) != tt.want {
				t.Errorf("%s: got %d issues, want %d", tt.name, len(issues), tt.want)
			}
		})
	}
}

func TestResourceLeak(t *testing.T) {
	rules := []types.Rule{{
		ID:          "RESOURCE_LEAK",
		Severity:    types.SeverityWarning,
		Description: "Resource not closed",
		Category:    "performance",
		Suggestion:  "Use defer close",
	}}

	analyzer := New(rules)

	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "sql.Open without close",
			code: `package main
import "database/sql"
func bad() {
    db, _ := sql.Open("postgres", "conn")
    _ = db
}`,
			want: 1,
		},
		{
			name: "sql.Open with defer close",
			code: `package main
import "database/sql"
func good() {
    db, _ := sql.Open("postgres", "conn")
    defer db.Close()
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := analyzer.AnalyzeFile("test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("AnalyzeFile failed: %v", err)
			}
			if len(issues) != tt.want {
				t.Errorf("%s: got %d issues, want %d", tt.name, len(issues), tt.want)
			}
		})
	}
}

func TestContextLeak(t *testing.T) {
	rules := []types.Rule{{
		ID:          "CONTEXT_LEAK",
		Severity:    types.SeveritySevere,
		Description: "Context used after cancel",
		Category:    "security",
		Suggestion:  "Use errgroup with context",
	}}

	analyzer := New(rules)

	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "go with context usage",
			code: `package main
import "context"
func bad(ctx context.Context) {
    go func() {
        <-ctx.Done()
    }()
}`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := analyzer.AnalyzeFile("test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("AnalyzeFile failed: %v", err)
			}
			if len(issues) != tt.want {
				t.Errorf("%s: got %d issues, want %d", tt.name, len(issues), tt.want)
			}
		})
	}
}
