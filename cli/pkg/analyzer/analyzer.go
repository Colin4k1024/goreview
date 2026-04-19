package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"

	"github.com/Colin4k1024/goreview/cli/pkg/types"
)

type Analyzer struct {
	rules  []types.Rule
	issues []types.Issue
	fset   *token.FileSet
}

func containsLower(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func New(rules []types.Rule) *Analyzer {
	return &Analyzer{rules: rules, issues: []types.Issue{}, fset: token.NewFileSet()}
}

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
	a.issues = deduplicateIssues(a.issues)
	return a.issues, nil
}

func deduplicateIssues(issues []types.Issue) []types.Issue {
	seen := make(map[string]types.Issue)
	for _, issue := range issues {
		key := fmt.Sprintf("%s:%d:%s", issue.File, issue.Line, issue.RuleID)
		seen[key] = issue
	}
	result := make([]types.Issue, 0, len(seen))
	for _, issue := range seen {
		result = append(result, issue)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].File != result[j].File {
			return result[i].File < result[j].File
		}
		return result[i].Line < result[j].Line
	})
	return result
}

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
	case "JWT_ERROR":
		a.checkJWTError(file, filePath, rule)
	case "HARDCODED_SECRET":
		a.checkHardcodedSecret(file, filePath, rule)
	case "ERROR_SWALLOW":
		a.checkErrorSwallow(file, filePath, rule)
	}
}

func (a *Analyzer) checkSQLInjection(file *ast.File, filePath string, rule types.Rule) {
	sqlMethods := map[string]bool{"query": true, "queryrow": true, "exec": true, "prepare": true}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			isSQLContext := false
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sqlMethods[strings.ToLower(sel.Sel.Name)] {
					isSQLContext = true
				}
			}
			if isSQLContext && len(call.Args) > 0 {
				for _, arg := range call.Args {
					if binOp, ok := arg.(*ast.BinaryExpr); ok && binOp.Op == token.ADD {
						pos := a.fset.Position(call.Pos())
						a.issues = append(a.issues, types.Issue{
							ID: rule.ID, Severity: rule.Severity, Title: "Potential SQL Injection",
							Message: "String concatenation used in SQL query. Use parameterized queries instead.",
							File: filePath, Line: pos.Line, RuleID: rule.ID,
							Suggestion: "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = $1\", userID)",
							Source: "static",
						})
						break
					}
				}
			}
		}
		return true
	})
}

func (a *Analyzer) checkSensitiveLog(file *ast.File, filePath string, rule types.Rule) {
	sensitivePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api_key|apikey|auth|bearer|credential)\b`),
		regexp.MustCompile(`(?i)\b(email|phone|ssn|credit|card|social.?security)\b`),
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			var fnName string
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				fnName = sel.Sel.Name
			} else if ident, ok := call.Fun.(*ast.Ident); ok {
				fnName = ident.Name
			}
			if strings.Contains(fnName, "Print") || strings.Contains(fnName, "Log") ||
				strings.Contains(fnName, "Debug") || strings.Contains(fnName, "Error") {
				for _, arg := range call.Args {
					if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						for _, pattern := range sensitivePatterns {
							if pattern.MatchString(lit.Value) {
								pos := a.fset.Position(call.Pos())
								a.issues = append(a.issues, types.Issue{
									ID: rule.ID, Severity: rule.Severity, Title: "Sensitive Data Logging",
									Message: fmt.Sprintf("Possible sensitive data '%s' logged. Avoid logging PII, tokens, passwords.", pattern.FindString(lit.Value)),
									File: filePath, Line: pos.Line, RuleID: rule.ID,
									Suggestion: "Remove sensitive fields from log messages. Log only user IDs or hashes.",
									Source: "static",
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

func (a *Analyzer) checkGoroutineLeak(file *ast.File, filePath string, rule types.Rule) {
	usesErrgroup := false
	for _, imp := range file.Imports {
		if imp.Path.Value == `"golang.org/x/sync/errgroup"` {
			usesErrgroup = true
			break
		}
	}
	if usesErrgroup {
		return
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if gen, ok := n.(*ast.GoStmt); ok {
			pos := a.fset.Position(gen.Go)
			a.issues = append(a.issues, types.Issue{
				ID: rule.ID, Severity: rule.Severity, Title: "Potential Goroutine Leak",
				Message: "Goroutine started without errgroup. No guarantee of graceful shutdown.",
				File: filePath, Line: pos.Line, RuleID: rule.ID,
				Suggestion: "Use golang.org/x/sync/errgroup: g, ctx := errgroup.WithContext(ctx); g.Go(func() error { ... })",
				Source: "static",
			})
		}
		return true
	})
}

func (a *Analyzer) checkResourceLeak(file *ast.File, filePath string, rule types.Rule) {
	resourceTypes := []string{"DB", "Rows", "Stmt", "File", "Conn", "Client", "Redis", "Response", "Body"}
	opened := map[string]token.Pos{}
	closed := map[string]bool{}

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
							if base, ok := sel.X.(*ast.Ident); ok && base.Name == "sql" {
								switch sel.Sel.Name {
								case "Open", "Query", "QueryRow", "Prepare", "Exec":
									for _, rt := range resourceTypes {
										if containsLower(ident.Name, rt) {
											opened[ident.Name] = call.Pos()
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
				ID: rule.ID, Severity: rule.Severity, Title: "Potential Resource Leak",
				Message: fmt.Sprintf("Resource '%s' appears to be opened but never closed.", name),
				File: filePath, Line: pos.Line, RuleID: rule.ID,
				Suggestion: "Ensure defer resource.Close() is called or use a wrapper that handles close automatically.",
				Source: "static",
			})
		}
	}
}

func (a *Analyzer) checkContextLeak(file *ast.File, filePath string, rule types.Rule) {
	ast.Inspect(file, func(n ast.Node) bool {
		if gen, ok := n.(*ast.GoStmt); ok {
			pos := a.fset.Position(gen.Go)
			if pos.Filename == filePath {
				a.issues = append(a.issues, types.Issue{
					ID: rule.ID, Severity: rule.Severity, Title: "Potential Context Leak",
					Message: "Goroutine uses context. Verify context is not cancelled before use in goroutine.",
					File: filePath, Line: pos.Line, RuleID: rule.ID,
					Suggestion: "Use golang.org/x/sync/errgroup or create a new context for the goroutine.",
					Source: "static",
				})
			}
		}
		return true
	})
}

func (a *Analyzer) checkJWTError(file *ast.File, filePath string, rule types.Rule) {
	jwtPackages := map[string]bool{
		`"github.com/golang-jwt/jwt/v5"`: true,
		`"github.com/dgrijalva/jwt-go"`:   true,
	}
	usesJWT := false
	for _, imp := range file.Imports {
		if jwtPackages[imp.Path.Value] {
			usesJWT = true
			break
		}
	}
	if !usesJWT {
		return
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Parse" {
				if len(call.Args) >= 2 && isNilExpr(call.Args[1]) {
					pos := a.fset.Position(call.Pos())
					a.issues = append(a.issues, types.Issue{
						ID: rule.ID, Severity: rule.Severity, Title: "JWT Parsed Without Signature Verification",
						Message: "jwt.Parse called with nil key function. Token signature is not verified.",
						File: filePath, Line: pos.Line, RuleID: rule.ID,
						Suggestion: "Always provide a key function to verify token signatures.",
						Source: "static",
					})
				}
			}
		}
		return true
	})
}

func isNilExpr(n ast.Expr) bool {
	if ident, ok := n.(*ast.Ident); ok {
		return ident.Name == "nil"
	}
	return false
}

func (a *Analyzer) checkHardcodedSecret(file *ast.File, filePath string, rule types.Rule) {
	secretStrPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)["']gh[pso]_[a-zA-Z0-9]{20,}["']`),
		regexp.MustCompile(`(?i)["']xox[baprs]-[a-zA-Z0-9-]{10,}["']`),
		regexp.MustCompile(`(?i)["'][a-zA-Z0-9+/]{32,}={0,2}["']`),
		regexp.MustCompile(`(?i)["'][a-fA-F0-9]{40}["']`),
	}
	secretNamePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(password|passwd|pwd|secret|token|api_key|apikey|auth|bearer|credential|private_?key)$`),
		regexp.MustCompile(`(?i)^(aws_|gcp_|azure_|stripe_|twilio_)`),
	}

	checkStr := func(lit *ast.BasicLit) bool {
		for _, p := range secretStrPatterns {
			if p.MatchString(lit.Value) {
				return true
			}
		}
		return false
	}
	checkName := func(name string) bool {
		for _, p := range secretNamePatterns {
			if p.MatchString(name) {
				return true
			}
		}
		return false
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if i >= len(node.Rhs) {
					continue
				}
				rhs := node.Rhs[i]
				if lit, ok := rhs.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					varName := ""
					if ident, ok := lhs.(*ast.Ident); ok {
						varName = ident.Name
					}
					if checkStr(lit) || checkName(varName) {
						pos := a.fset.Position(node.Pos())
						a.issues = append(a.issues, types.Issue{
							ID: rule.ID, Severity: rule.Severity, Title: "Hardcoded Secret Detected",
							Message: fmt.Sprintf("Variable '%s' may contain a hardcoded secret.", varName),
							File: filePath, Line: pos.Line, RuleID: rule.ID,
							Suggestion: "Use environment variables or a secrets manager (Vault, AWS Secrets Manager).",
							Source: "static",
						})
					}
				}
			}
		case *ast.GenDecl:
			for _, spec := range node.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for i, val := range vs.Values {
						if i >= len(vs.Names) {
							continue
						}
						varName := vs.Names[i].Name
						if lit, ok := val.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if checkStr(lit) || checkName(varName) {
								pos := a.fset.Position(node.Pos())
								a.issues = append(a.issues, types.Issue{
									ID: rule.ID, Severity: rule.Severity, Title: "Hardcoded Secret Detected",
									Message: fmt.Sprintf("Variable '%s' may contain a hardcoded secret.", varName),
									File: filePath, Line: pos.Line, RuleID: rule.ID,
									Suggestion: "Use environment variables or a secrets manager (Vault, AWS Secrets Manager).",
									Source: "static",
								})
							}
						}
					}
				}
			}
		}
		return true
	})
}

func (a *Analyzer) checkErrorSwallow(file *ast.File, filePath string, rule types.Rule) {
	_ = file
	_ = filePath
	_ = rule
}
