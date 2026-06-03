// Package main generates the error codes reference documentation from source code.
//
// It parses internal/errdef/errors.go using Go AST to extract custom application errors,
// and api/talos/v2alpha1/talos.proto using regex to extract error enum definitions.
//
// Usage:
//
//	go run ./tools/error-codes-gen > docs/reference/error-codes.md
package main

import (
	"cmp"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// AppError represents a custom application error extracted from errdef/errors.go.
type AppError struct {
	ID          string
	HTTPCode    int
	GRPCCode    string
	Description string
}

// EnumValue represents a single value in a protobuf error enum.
type EnumValue struct {
	Name    string
	Number  int
	Comment string
}

var (
	errUnexpectedAST = errors.New("unexpected AST node")
	errUnknownConst  = errors.New("unknown constant")
	errEnumNotFound  = errors.New("enum not found")
)

func httpStatusCodes() map[string]int {
	return map[string]int{
		"StatusBadRequest":          400,
		"StatusUnauthorized":        401,
		"StatusPaymentRequired":     402,
		"StatusForbidden":           403,
		"StatusNotFound":            404,
		"StatusConflict":            409,
		"StatusInternalServerError": 500,
		"StatusTooManyRequests":     429,
		"StatusServiceUnavailable":  503,
		"StatusGatewayTimeout":      504,
	}
}

func grpcCodeDisplayNames() map[string]string {
	return map[string]string{
		"InvalidArgument":    "INVALID_ARGUMENT",
		"Unauthenticated":    "UNAUTHENTICATED",
		"NotFound":           "NOT_FOUND",
		"AlreadyExists":      "ALREADY_EXISTS",
		"FailedPrecondition": "FAILED_PRECONDITION",
		"Unimplemented":      "UNIMPLEMENTED",
		"Unavailable":        "UNAVAILABLE",
		"DeadlineExceeded":   "DEADLINE_EXCEEDED",
		"Internal":           "INTERNAL",
		"PermissionDenied":   "PERMISSION_DENIED",
		"ResourceExhausted":  "RESOURCE_EXHAUSTED",
	}
}

func main() {
	appErrors, err := parseAppErrors("internal/errdef/errors.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing errdef/errors.go: %v\n", err)
		os.Exit(1)
	}
	if len(appErrors) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no custom errors found in errdef/errors.go\n")
		os.Exit(1)
	}

	verificationCodes, err := parseProtoEnum("api/talos/v2alpha1/talos.proto", "VerificationErrorCode")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing VerificationErrorCode: %v\n", err)
		os.Exit(1)
	}

	batchImportCodes, err := parseProtoEnum("api/talos/v2alpha1/talos.proto", "BatchCreateImportedApiKeysErrorCode")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing BatchCreateImportedApiKeysErrorCode: %v\n", err)
		os.Exit(1)
	}

	// Sort application errors by HTTP code, then by ID.
	slices.SortFunc(appErrors, func(a, b AppError) int {
		if a.HTTPCode != b.HTTPCode {
			return cmp.Compare(a.HTTPCode, b.HTTPCode)
		}
		return cmp.Compare(a.ID, b.ID)
	})

	// Proto enum values are kept in proto field number order.
	slices.SortFunc(verificationCodes, func(a, b EnumValue) int {
		return cmp.Compare(a.Number, b.Number)
	})
	slices.SortFunc(batchImportCodes, func(a, b EnumValue) int {
		return cmp.Compare(a.Number, b.Number)
	})

	printFrontmatter()
	printIntro()
	printAppErrorsTable(appErrors)
	printStandardHTTPTable()
	printVerificationCodesTable(verificationCodes)
	printBatchImportCodesTable(batchImportCodes)
	printRecommendations()
}

func parseAppErrors(path string) ([]AppError, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var appErrors []AppError
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			continue
		}
		if !returnsHerodotDefaultError(fn.Type.Results) {
			continue
		}
		comp, ok := findHerodotReturnLiteral(fn.Body)
		if !ok {
			continue
		}
		ae, err := extractErrorFields(comp)
		if err != nil {
			return nil, fmt.Errorf("extracting fields from %s: %w", fn.Name.Name, err)
		}
		appErrors = append(appErrors, ae)
	}
	return appErrors, nil
}

// returnsHerodotDefaultError reports whether the function returns exactly one
// *herodot.DefaultError result.
func returnsHerodotDefaultError(results *ast.FieldList) bool {
	if results == nil || len(results.List) != 1 {
		return false
	}
	field := results.List[0]
	if len(field.Names) > 1 {
		return false
	}
	star, ok := field.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "herodot" && sel.Sel.Name == "DefaultError"
}

// findHerodotReturnLiteral walks the body for the first
// `return &herodot.DefaultError{...}` statement and returns its composite literal.
func findHerodotReturnLiteral(body *ast.BlockStmt) (*ast.CompositeLit, bool) {
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		unary, ok := ret.Results[0].(*ast.UnaryExpr)
		if !ok || unary.Op != token.AND {
			continue
		}
		comp, ok := unary.X.(*ast.CompositeLit)
		if !ok {
			continue
		}
		sel, ok := comp.Type.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "herodot" || sel.Sel.Name != "DefaultError" {
			continue
		}
		return comp, true
	}
	return nil, false
}

func extractErrorFields(comp *ast.CompositeLit) (AppError, error) {
	var ae AppError
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "IDField":
			ae.ID = extractStringLit(kv.Value)
		case "ErrorField":
			ae.Description = extractStringLit(kv.Value)
		case "CodeField":
			code, err := resolveHTTPStatus(kv.Value)
			if err != nil {
				return ae, err
			}
			ae.HTTPCode = code
		case "GRPCCodeField":
			name, err := resolveGRPCCode(kv.Value)
			if err != nil {
				return ae, err
			}
			ae.GRPCCode = name
		}
	}
	return ae, nil
}

func extractStringLit(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return lit.Value
	}
	return s
}

func resolveHTTPStatus(expr ast.Expr) (int, error) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return 0, fmt.Errorf("CodeField: expected selector, got %T: %w", expr, errUnexpectedAST)
	}
	code, ok := httpStatusCodes()[sel.Sel.Name]
	if !ok {
		return 0, fmt.Errorf("http.%s: %w", sel.Sel.Name, errUnknownConst)
	}
	return code, nil
}

func resolveGRPCCode(expr ast.Expr) (string, error) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", fmt.Errorf("GRPCCodeField: expected selector, got %T: %w", expr, errUnexpectedAST)
	}
	display, ok := grpcCodeDisplayNames()[sel.Sel.Name]
	if !ok {
		return "", fmt.Errorf("codes.%s: %w", sel.Sel.Name, errUnknownConst)
	}
	return display, nil
}

func parseProtoEnum(path, enumName string) ([]EnumValue, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	enumRe := regexp.MustCompile(`^\s*enum\s+` + regexp.QuoteMeta(enumName) + `\s*\{`)
	valueRe := regexp.MustCompile(`^\s+(\w+)\s*=\s*(\d+)\s*;(?:\s*//\s*(.*))?`)

	values := make([]EnumValue, 0, 8)
	inEnum := false
	for _, line := range lines {
		if !inEnum {
			if enumRe.MatchString(line) {
				inEnum = true
			}
			continue
		}
		if strings.TrimSpace(line) == "}" {
			break
		}
		m := valueRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		num, _ := strconv.Atoi(m[2])
		comment := strings.TrimSpace(m[3])
		if comment == "" {
			comment = enumNameToDescription(m[1])
		}
		values = append(values, EnumValue{
			Name:    m[1],
			Number:  num,
			Comment: comment,
		})
	}
	if !inEnum {
		return nil, fmt.Errorf("%s in %s: %w", enumName, path, errEnumNotFound)
	}
	return values, nil
}

// enumNameToDescription converts an enum value name to a readable fallback description.
// e.g., "BATCH_CREATE_IMPORTED_API_KEYS_ERROR_ALREADY_EXISTS" -> "Already exists".
func enumNameToDescription(name string) string {
	// Strip known prefixes.
	for _, prefix := range []string{"VERIFICATION_ERROR_", "BATCH_IMPORT_ERROR_"} {
		if after, found := strings.CutPrefix(name, prefix); found {
			name = after
			break
		}
	}
	words := strings.Split(strings.ToLower(name), "_")
	if len(words) > 0 {
		words[0] = strings.ToUpper(words[0][:1]) + words[0][1:]
	}
	return strings.Join(words, " ")
}

// padRight pads s with spaces to the given width.
func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func printFrontmatter() {
	fmt.Println(`---
title: Error codes
description: HTTP and gRPC error codes returned by the Talos API
---

<!-- This file is auto-generated by tools/error-codes-gen. Do not edit manually. -->
<!-- Source of truth: internal/errdef/errors.go, api/talos/v2alpha1/talos.proto -->`)
}

func printIntro() {
	fmt.Print(`
# Error codes

Talos returns structured error responses following the [herodot](https://github.com/ory/herodot)
error format. Every error response includes an ` + "`id`" + `, HTTP status code, status text, and a
human-readable message.

## Error response format

` + "```json" + `
{
  "error": {
    "code": 400,
    "status": "Bad Request",
    "message": "The API key format is invalid.",
    "reason": "Additional context about the error"
  }
}
` + "```" + `

## Application errors

`)
}

func printAppErrorsTable(appErrors []AppError) {
	// Compute column widths for aligned output.
	idW, httpW, grpcW, descW := len("Error ID"), len("HTTP"), len("gRPC"), len("Description")
	for _, e := range appErrors {
		id := fmt.Sprintf("`%s`", e.ID)
		if len(id) > idW {
			idW = len(id)
		}
		code := strconv.Itoa(e.HTTPCode)
		if len(code) > httpW {
			httpW = len(code)
		}
		grpc := fmt.Sprintf("`%s`", e.GRPCCode)
		if len(grpc) > grpcW {
			grpcW = len(grpc)
		}
		if len(e.Description) > descW {
			descW = len(e.Description)
		}
	}

	// Header
	fmt.Printf("| %s | %s | %s | %s |\n",
		padRight("Error ID", idW),
		padRight("HTTP", httpW),
		padRight("gRPC", grpcW),
		padRight("Description", descW))
	fmt.Printf("| %s | %s | %s | %s |\n",
		strings.Repeat("-", idW),
		strings.Repeat("-", httpW),
		strings.Repeat("-", grpcW),
		strings.Repeat("-", descW))

	// Rows
	for _, e := range appErrors {
		fmt.Printf("| %s | %s | %s | %s |\n",
			padRight(fmt.Sprintf("`%s`", e.ID), idW),
			padRight(strconv.Itoa(e.HTTPCode), httpW),
			padRight(fmt.Sprintf("`%s`", e.GRPCCode), grpcW),
			padRight(e.Description, descW))
	}
}

func printStandardHTTPTable() {
	fmt.Print(`
## Standard HTTP errors

| Error ID                         | HTTP | Description              |
| -------------------------------- | ---- | ------------------------ |
| Standard ` + "`bad_request`" + `           | 400  | Generic validation error |
| Standard ` + "`unauthorized`" + `          | 401  | Authentication required  |
| Standard ` + "`forbidden`" + `             | 403  | Insufficient permissions |
| Standard ` + "`not_found`" + `             | 404  | Resource not found       |
| Standard ` + "`conflict`" + `              | 409  | Resource conflict        |
| Standard ` + "`internal_server_error`" + ` | 500  | Unexpected server error  |

`)
}

func printVerificationCodesTable(values []EnumValue) {
	fmt.Print(`## Verification error codes

The ` + "`VerifyAPIKey`" + ` response includes an ` + "`error_code`" + ` enum when verification fails:

`)
	printEnumTable(values)
}

func printBatchImportCodesTable(values []EnumValue) {
	fmt.Print(`
## Batch import error codes

The ` + "`BatchImportAPIKeys`" + ` response includes per-item error codes:

`)
	printEnumTable(values)
}

func printEnumTable(values []EnumValue) {
	// Compute column widths.
	codeW, meaningW := len("Code"), len("Meaning")
	for _, v := range values {
		code := fmt.Sprintf("`%s`", v.Name)
		if len(code) > codeW {
			codeW = len(code)
		}
		if len(v.Comment) > meaningW {
			meaningW = len(v.Comment)
		}
	}

	fmt.Printf("| %s | %s |\n",
		padRight("Code", codeW),
		padRight("Meaning", meaningW))
	fmt.Printf("| %s | %s |\n",
		strings.Repeat("-", codeW),
		strings.Repeat("-", meaningW))
	for _, v := range values {
		fmt.Printf("| %s | %s |\n",
			padRight(fmt.Sprintf("`%s`", v.Name), codeW),
			padRight(v.Comment, meaningW))
	}
}

func printRecommendations() {
	fmt.Print(`
## Error handling recommendations

- **4xx errors**: Fix the request and retry. Do not retry without changes.
- **409 Conflict**: Check if the resource already exists or is in an incompatible state.
- **5xx errors**: Retry with exponential backoff and jitter.
- **503 Service Unavailable**: The server is temporarily overloaded. Retry after the ` + "`Retry-After`" + `
  header value if present.
`)
}
