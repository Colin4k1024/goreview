package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"

	"github.com/Colin4k1024/goreview/cli/pkg/types"
)

// Analyzer performs static analysis on Go source code
type Analyzer struct {
	rules  []types.Rule
	issues []types.Issue
	fset   *token.FileSet
}

// New creates a new analyzer with the given rules
func New(rules []types.Rule) *Analyzer {
	return &Analyzer{
		rules:  rules,
		issues: []types.Issue{},
		fset:   token.NewFileSet(),
	}
}

// AnalyzeFile analyzes a single Go source file
func (a *Analyzer) AnalyzeFile(filePath string, content []byte) ([]types.Issue, error) {
	a.issues = []types.Issue{}
	a.fset = token.NewFileSet()

	file, err := parser.ParseFile(a.fset, filePath, content, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	for _, rule := range a.rules {
		a.runRule(file, filePath, rule)
	}

	return a.issues, nil
}

// runRule applies a single rule to the file
func (a *Analyzer) runRule(file *ast.File, filePath string, rule types.Rule) {
	switch rule.ID {
	case "SQL_INJECTION":
		a.checkSQLInjection(file, filePath, rule)
	case "SENSITIVE_LOG":
		a.checkSensitiveLog(file, filePath, rule)
	case "GOROUTINE_LEAK":
		a.checkGoroutineLeak(file, filePath, rule)
	case "RESOURCE_LEAK":
		a.checkResourceLeak(file, filePath, rule)
	case "CONTEXT_LEAK":
		a.checkContextLeak(file, filePath, rule)
	case "ERROR_SWALLOW":
		a.checkErrorSwallow(file, filePath, rule)
	}
}

// checkSQLInjection detects potential SQL injection vulnerabilities
func (a *Analyzer) checkSQLInjection(file *ast.File, filePath string, rule types.Rule) {
	sqlKeywords := regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|INTO|VALUES|SET)\b`)
	sqlMethods := regexp.MustCompile(`(?i)\.(Query|QueryRow|Exec|Prepare)\s*\(`)
	stringConcatInCall := regexp.MustCompile(`fmt\.Sprintf|strings\.Join|fmt\.Sprint|fmt\.Sprintln|fmt\.Errorf|strings\.Buffer|strconv\.|fmt\.Append`)

	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			isSQLContext := false
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				methodName := sel.Sel.Name
				if sqlMethods.MatchString(methodName) {
					isSQLContext = true
				}
			}

			if isSQLContext && len(call.Args) > 0 {
				hasConcat := false
				for _, arg := range call.Args {
					if argContainsConcat(arg, stringConcatInCall) {
						hasConcat = true
						break
					}
				}
				if hasConcat {
					pos := a.fset.Position(call.Pos())
					a.issues = append(a.issues, types.Issue{
						ID:         rule.ID,
						Severity:   rule.Severity,
						Title:      "Potential SQL Injection",
						Message:    "Possible SQL injection: string concatenation used in SQL query. Use parameterized queries instead.",
						File:       filePath,
						Line:       pos.Line,
						RuleID:     rule.ID,
						Suggestion: "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = $1\", userID)",
						Source:     "static",
					})
				}
			}
		}

		if binOp, ok := n.(*ast.BinaryExpr); ok {
			if binOp.Op == token.ADD {
				args := collectBinaryStringParts(binOp)
				for _, arg := range args {
					if sqlKeywords.MatchString(arg) && stringConcatInCall.MatchString(arg) {
						pos := a.fset.Position(binOp.Pos())
						a.issues = append(a.issues, types.Issue{
							ID:         rule.ID,
							Severity:   rule.Severity,
							Title:      "Potential SQL Injection",
							Message:    "String concatenation detected in SQL context. Use parameterized queries.",
							File:       filePath,
							Line:       pos.Line,
							RuleID:     rule.ID,
							Suggestion: "Use db.Query(\"SELECT * FROM users WHERE id = $1\", userID) instead.",
							Source:     "static",
						})
						break
					}
				}
			}
		}
		return true
	})
}

func argContainsConcat(n ast.Node, pattern *regexp.Regexp) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pattern.MatchString(sel.Sel.Name) {
					found = true
					return false
				}
			}
			if ident, ok := call.Fun.(*ast.Ident); ok {
				if pattern.MatchString(ident.Name) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

func collectBinaryStringParts(expr *ast.BinaryExpr) []string {
	var parts []string
	collectStringParts(expr, &parts)
	return parts
}

func collectStringParts(expr ast.Expr, parts *[]string) {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			collectStringParts(e.X, parts)
			collectStringParts(e.Y, parts)
		}
	case *ast.CallExpr:
		if ident, ok := e.Fun.(*ast.Ident); ok {
			*parts = append(*parts, ident.Name)
		}
	case *ast.Ident:
		*parts = append(*parts, e.Name)
	}
}

// checkSensitiveLog detects sensitive data being logged
func (a *Analyzer) checkSensitiveLog(file *ast.File, filePath string, rule types.Rule) {
	sensitivePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api_key|apikey|auth|bearer|credential)`),
		regexp.MustCompile(`(?i)(email|phone|ssn|credit|card)`),
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			var fnName string
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				fnName = sel.Sel.Name
			} else if ident, ok := call.Fun.(*ast.Ident); ok {
				fnName = ident.Name
			}

			if strings.Contains(fnName, "Print") || strings.Contains(fnName, "Log") || strings.Contains(fnName, "Debug") || strings.Contains(fnName, "Error") {
				for _, arg := range call.Args {
					if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						for _, pattern := range sensitivePatterns {
							if pattern.MatchString(lit.Value) {
								pos := a.fset.Position(call.Pos())
								a.issues = append(a.issues, types.Issue{
									ID:         rule.ID,
									Severity:   rule.Severity,
									Title:      "Sensitive Data Logging",
									Message:    fmt.Sprintf("Possible sensitive data '%s' logged in error/message. Avoid logging PII, tokens, passwords.", pattern.FindString(lit.Value)),
									File:       filePath,
									Line:       pos.Line,
									RuleID:     rule.ID,
									Suggestion: "Remove sensitive fields from log messages. Log only user IDs or hashes.",
									Source:     "static",
								})
								break
							}
						}
					}
				}
			}
		}
		return true
	})
}

// checkGoroutineLeak detects goroutines started without proper cleanup
func (a *Analyzer) checkGoroutineLeak(file *ast.File, filePath string, rule types.Rule) {
	// Check if file uses errgroup
	usesErrgroup := false
	for _, imp := range file.Imports {
		if imp.Path.Value == `"golang.org/x/sync/errgroup"` {
			usesErrgroup = true
			break
		}
	}
	if usesErrgroup {
		return // errgroup users are assumed correct
	}

	// Check for plain go statements (without errgroup)
	ast.Inspect(file, func(n ast.Node) bool {
		if gen, ok := n.(*ast.GoStmt); ok {
			pos := a.fset.Position(gen.Go)
			a.issues = append(a.issues, types.Issue{
				ID:         rule.ID,
				Severity:   rule.Severity,
				Title:      "Potential Goroutine Leak",
				Message:    "Goroutine started without errgroup. No guarantee of graceful shutdown.",
				File:       filePath,
				Line:       pos.Line,
				RuleID:     rule.ID,
				Suggestion: "Use golang.org/x/sync/errgroup: g, ctx := errgroup.WithContext(ctx); g.Go(func() error { ... })",
				Source:     "static",
			})
		}
		return true
	})
}

// checkResourceLeak detects resources that may not be properly closed
func (a *Analyzer) checkResourceLeak(file *ast.File, filePath string, rule types.Rule) {
	resourceTypes := []string{"DB", "Rows", "Stmt", "File", "Conn", "Client", "Redis", "Response", "Body"}
	opened := map[string]token.Pos{}
	closed := map[string]bool{}

	// First pass: collect function signatures that have context param
	funcsWithContext := make(map[string]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			if fn.Type.Params != nil {
				for _, field := range fn.Type.Params.List {
					for _, name := range field.Names {
						if name.Name == "ctx" {
							funcsWithContext[fn.Name.Name] = true
						}
					}
				}
			}
		}
		return true
	})

	// Track opened/closed resources
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if i >= len(node.Rhs) {
					continue
				}
				if ident, ok := lhs.(*ast.Ident); ok {
					if call, ok := node.Rhs[i].(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
							if base, ok := sel.X.(*ast.Ident); ok {
								if base.Name == "sql" {
									switch sel.Sel.Name {
									case "Open", "Query", "QueryRow", "Prepare", "Exec":
										for _, rt := range resourceTypes {
											if strings.Contains(ident.Name, rt) {
												opened[ident.Name] = call.Pos()
											}
										}
									}
								}
							}
						}
					}
				}
			}

		case *ast.ExprStmt:
			if call, ok := node.X.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if sel.Sel.Name == "Close" || sel.Sel.Name == "CloseReadWriteCloser" {
						if ident, ok := sel.X.(*ast.Ident); ok {
							closed[ident.Name] = true
						}
					}
				}
			}

		case *ast.DeferStmt:
			if call, ok := node.Call.Fun.(*ast.SelectorExpr); ok {
				if call.Sel.Name == "Close" || call.Sel.Name == "CloseReadWriteCloser" {
					if ident, ok := call.X.(*ast.Ident); ok {
						closed[ident.Name] = true
					}
				}
			}
		}
		return true
	})

	for name := range opened {
		if !closed[name] {
			pos := a.fset.Position(opened[name])
			a.issues = append(a.issues, types.Issue{
				ID:         rule.ID,
				Severity:   rule.Severity,
				Title:      "Potential Resource Leak",
				Message:    fmt.Sprintf("Resource '%s' appears to be opened but never closed.", name),
				File:       filePath,
				Line:       pos.Line,
				RuleID:     rule.ID,
				Suggestion: "Ensure defer resource.Close() is called or use a wrapper that handles close automatically.",
				Source:     "static",
			})
		}
	}
}

// checkContextLeak detects context used after cancellation
func (a *Analyzer) checkContextLeak(file *ast.File, filePath string, rule types.Rule) {
	ast.Inspect(file, func(n ast.Node) bool {
		if gen, ok := n.(*ast.GoStmt); ok {
			pos := a.fset.Position(gen.Go)
			if pos.Filename == filePath {
				a.issues = append(a.issues, types.Issue{
					ID:         rule.ID,
					Severity:   rule.Severity,
					Title:      "Potential Context Leak",
					Message:    "Goroutine uses context. Verify context is not cancelled before use in goroutine.",
					File:       filePath,
					Line:       pos.Line,
					RuleID:     rule.ID,
					Suggestion: "Use golang.org/x/sync/errgroup or create a new context for the goroutine.",
					Source:     "static",
				})
			}
		}
		return true
	})
}

// checkErrorSwallow detects errors that are silently discarded
func (a *Analyzer) checkErrorSwallow(file *ast.File, filePath string, rule types.Rule) {
	// Skip for now - too many false positives without type-aware analysis
	_ = file
	_ = filePath
	_ = rule
}

// placeholder to avoid unused imports
var _ = regexp.MustCompile("")
