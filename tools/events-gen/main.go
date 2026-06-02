// Package main generates the audit events reference documentation from source code.
//
// It parses internal/events/events.go and internal/events/attributes.go using Go AST
// to extract event types, results, struct fields, and OTEL attribute keys.
//
// Usage:
//
//	go run ./tools/events-gen > docs/reference/events.md
package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
)

// EventTypeConst represents an extracted EventType constant.
type EventTypeConst struct {
	Name    string // Go constant name (e.g., "EventIssuedAPIKeyCreated")
	Value   string // String value (e.g., "api_key.created")
	Comment string // Doc comment
}

// StructField represents a field from the AuditEvent struct.
type StructField struct {
	Name     string // Go field name
	JSONTag  string // JSON tag value
	Type     string // Go type
	Comment  string // Inline or doc comment
	Optional bool   // Has omitempty
}

// AttrConst represents an extracted attribute constant.
type AttrConst struct {
	Name    string // Go constant name (e.g., "AttrEventType")
	Value   string // String value (e.g., "event.type")
	Comment string // Doc comment
}

var errNoConstants = errors.New("no constants found")

func main() {
	eventTypes, _, err := parseEventsFile("pkg/semconv/events.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing semconv/events.go: %v\n", err)
		os.Exit(1)
	}

	_, fields, err := parseEventsFile("internal/events/events.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing events/events.go: %v\n", err)
		os.Exit(1)
	}

	attrs, err := parseAttributesFile("internal/events/attributes.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing attributes.go: %v\n", err)
		os.Exit(1)
	}

	if len(eventTypes) == 0 {
		fmt.Fprintf(os.Stderr, "Error: %v in events.go\n", errNoConstants)
		os.Exit(1)
	}

	printFrontmatter()
	printIntro()
	printEventTypesTable(eventTypes)
	printAttributesTable(attrs, fields)
	printMetadataSection()
	printUsageExample()
}

func parseEventsFile(path string) ([]EventTypeConst, []StructField, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var (
		eventTypes []EventTypeConst
		fields     []StructField
	)

	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		switch genDecl.Tok { //nolint:exhaustive // Only CONST and TYPE declarations are relevant.
		case token.CONST:
			for _, spec := range genDecl.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Values) != 1 {
					continue
				}

				typeName := resolveTypeName(vs)
				if typeName != "Event" {
					continue
				}

				eventTypes = append(eventTypes, EventTypeConst{
					Name:    vs.Names[0].Name,
					Value:   extractStringLit(vs.Values[0]),
					Comment: extractSpecComment(vs),
				})
			}
		case token.TYPE:
			for _, spec := range genDecl.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "AuditEvent" {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				fields = extractStructFields(st)
			}
		default:
			// Other token types (VAR, FUNC, IMPORT, etc.) are not relevant
			// for event type or struct extraction; skip them.
		}
	}

	return eventTypes, fields, nil
}

func parseAttributesFile(path string) ([]AttrConst, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var attrs []AttrConst
	for _, decl := range f.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) != 1 {
				continue
			}

			name := vs.Names[0].Name
			if !strings.HasPrefix(name, "Attr") {
				continue
			}

			value := extractStringLit(vs.Values[0])
			comment := extractSpecComment(vs)

			attrs = append(attrs, AttrConst{
				Name:    name,
				Value:   value,
				Comment: comment,
			})
		}
	}

	return attrs, nil
}

// resolveTypeName extracts the type name from a ValueSpec.
// It handles both explicit types (e.g., `EventType = "..."`) and
// iota-style grouped constants where the type is on the first spec.
func resolveTypeName(vs *ast.ValueSpec) string {
	if vs.Type == nil {
		return ""
	}
	switch t := vs.Type.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

func extractStringLit(expr ast.Expr) string {
	// Handle semconv.AttributeKey("value") or similar call expressions
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 1 {
		return extractStringLit(call.Args[0])
	}
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

func extractSpecComment(vs *ast.ValueSpec) string {
	if vs.Doc != nil {
		return cleanComment(vs.Doc.Text())
	}
	if vs.Comment != nil {
		return cleanComment(vs.Comment.Text())
	}
	return ""
}

func cleanComment(s string) string {
	s = strings.TrimSpace(s)
	// Remove common prefixes like "EventIssuedAPIKeyCreated is emitted when..."
	// We keep the full comment as-is since it's already descriptive.
	return s
}

func extractStructFields(st *ast.StructType) []StructField {
	var fields []StructField
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			continue // embedded field
		}

		sf := StructField{
			Name: field.Names[0].Name,
			Type: typeToString(field.Type),
		}

		if field.Tag != nil {
			tag, err := strconv.Unquote(field.Tag.Value)
			if err == nil {
				sf.JSONTag, sf.Optional = parseJSONTag(tag)
			}
		}

		sf.Comment = extractFieldComment(field)

		fields = append(fields, sf)
	}
	return fields
}

func typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok {
			return x.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.MapType:
		return "map[" + typeToString(t.Key) + "]" + typeToString(t.Value)
	case *ast.ArrayType:
		return "[]" + typeToString(t.Elt)
	case *ast.StarExpr:
		return "*" + typeToString(t.X)
	}
	return "unknown"
}

func parseJSONTag(tag string) (name string, omitempty bool) {
	// Parse `json:"field_name,omitempty"` from the full struct tag.
	const prefix = `json:"`
	_, after, found := strings.Cut(tag, prefix)
	if !found {
		return "", false
	}
	jsonVal, _, found := strings.Cut(after, `"`)
	if !found {
		return "", false
	}
	parts := strings.Split(jsonVal, ",")
	name = parts[0]
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omitempty = true
		}
	}
	return name, omitempty
}

func extractFieldComment(field *ast.Field) string {
	if field.Doc != nil {
		return strings.TrimSpace(field.Doc.Text())
	}
	if field.Comment != nil {
		return strings.TrimSpace(field.Comment.Text())
	}
	return ""
}

// padRight pads s with spaces to the given width.
func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// attrToField maps attribute constant names to AuditEvent field names.
func attrToField() map[string]string {
	return map[string]string{
		"AttrNetworkID":      "NetworkID",
		"AttrKeyID":          "KeyID",
		"AttrAPIKeyPrefix":   "Prefix",
		"AttrKeyType":        "KeyType",
		"AttrOperation":      "Operation",
		"AttrReason":         "Reason",
		"AttrActorID":        "ActorID",
		"AttrExpiry":         "Expiry",
		"AttrVisibility":     "Visibility",
		"AttrMetadataPrefix": "Metadata",
	}
}

func printFrontmatter() {
	fmt.Println(`---
title: Audit events
description: Structured audit events emitted by Talos via OpenTelemetry
---

<!-- This file is auto-generated by tools/events-gen. Do not edit manually. -->
<!-- Source of truth: internal/events/events.go, internal/events/attributes.go -->`)
}

func printIntro() {
	fmt.Print(`
# Audit events

Talos emits structured audit events via OpenTelemetry span events for all significant lifecycle
operations. Events are attached to the active OTEL span and forwarded to any configured OTEL
collector. They are never persisted locally.

Each event carries a set of structured attributes that provide context about the operation,
the actor, and the affected resource.

`)
}

// constTableEntry is a generic row for the three-column constant tables.
type constTableEntry struct {
	Name    string
	Value   string
	Comment string
}

// printConstTable prints a markdown table with Constant, valueHeader, and Description columns.
func printConstTable(heading, valueHeader string, entries []constTableEntry) {
	fmt.Printf("## %s\n\n", heading)

	nameW, valueW, descW := len("Constant"), len(valueHeader), len("Description")
	for _, e := range entries {
		if n := len(e.Name) + 2; n > nameW { // +2 for backticks
			nameW = n
		}
		if v := len(e.Value) + 2; v > valueW {
			valueW = v
		}
		if len(e.Comment) > descW {
			descW = len(e.Comment)
		}
	}

	fmt.Printf("| %s | %s | %s |\n",
		padRight("Constant", nameW),
		padRight(valueHeader, valueW),
		padRight("Description", descW))
	fmt.Printf("| %s | %s | %s |\n",
		strings.Repeat("-", nameW),
		strings.Repeat("-", valueW),
		strings.Repeat("-", descW))
	for _, e := range entries {
		fmt.Printf("| %s | %s | %s |\n",
			padRight(fmt.Sprintf("`%s`", e.Name), nameW),
			padRight(fmt.Sprintf("`%s`", e.Value), valueW),
			padRight(e.Comment, descW))
	}
	fmt.Println()
}

func printEventTypesTable(types []EventTypeConst) {
	entries := make([]constTableEntry, len(types))
	for i, t := range types {
		entries[i] = constTableEntry(t)
	}
	printConstTable("Event types", "Event Name", entries)
}

func printAttributesTable(attrs []AttrConst, fields []StructField) {
	fmt.Println(`## Event attributes`)
	fmt.Println()
	fmt.Println(`Each event carries the following OTEL span event attributes:`)
	fmt.Println()

	fieldMap := attrToField()
	fieldByName := make(map[string]StructField, len(fields))
	for _, f := range fields {
		fieldByName[f.Name] = f
	}

	type row struct {
		attrKey  string
		field    string
		typ      string
		required string
		desc     string
	}

	rows := make([]row, 0, len(attrs))
	for _, a := range attrs {
		fieldName := fieldMap[a.Name]
		sf := fieldByName[fieldName]

		required := "Required"
		if sf.Optional {
			required = "Optional"
		}
		// MetadataPrefix is always optional and dynamic
		if a.Name == "AttrMetadataPrefix" {
			required = "Optional"
		}

		typ := sf.Type
		if typ == "" {
			typ = "string"
		}

		// Prefer the struct field comment (more specific) over the attribute group comment.
		desc := sf.Comment
		if desc == "" {
			desc = a.Comment
		}

		rows = append(rows, row{
			attrKey:  a.Value,
			field:    fieldName,
			typ:      typ,
			required: required,
			desc:     desc,
		})
	}

	keyW, fieldW, typeW, reqW, descW := len("OTEL Key"), len("Struct Field"), len("Type"), len("Required"), len("Description")
	for _, r := range rows {
		key := fmt.Sprintf("`%s`", r.attrKey)
		if len(key) > keyW {
			keyW = len(key)
		}
		field := fmt.Sprintf("`%s`", r.field)
		if len(field) > fieldW {
			fieldW = len(field)
		}
		if len(r.typ) > typeW {
			typeW = len(r.typ)
		}
		if len(r.required) > reqW {
			reqW = len(r.required)
		}
		if len(r.desc) > descW {
			descW = len(r.desc)
		}
	}

	fmt.Printf("| %s | %s | %s | %s | %s |\n",
		padRight("OTEL Key", keyW),
		padRight("Struct Field", fieldW),
		padRight("Type", typeW),
		padRight("Required", reqW),
		padRight("Description", descW))
	fmt.Printf("| %s | %s | %s | %s | %s |\n",
		strings.Repeat("-", keyW),
		strings.Repeat("-", fieldW),
		strings.Repeat("-", typeW),
		strings.Repeat("-", reqW),
		strings.Repeat("-", descW))
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s | %s | %s |\n",
			padRight(fmt.Sprintf("`%s`", r.attrKey), keyW),
			padRight(fmt.Sprintf("`%s`", r.field), fieldW),
			padRight(r.typ, typeW),
			padRight(r.required, reqW),
			padRight(r.desc, descW))
	}
	fmt.Println()
}

func printMetadataSection() {
	fmt.Print(`## Dynamic metadata attributes

The ` + "`metadata.*`" + ` prefix supports arbitrary key-value pairs for event-specific context.
Metadata keys are prefixed with ` + "`metadata.`" + ` in OTEL attributes. For example, a metadata
entry ` + "`{\"token_type\": \"jwt\"}`" + ` becomes the OTEL attribute ` + "`metadata.token_type`" + `
with value ` + "`jwt`" + `.

Metadata is optional and varies by event type. Common metadata keys include:

- ` + "`token_type`" + ` — Type of derived token (e.g., ` + "`jwt`" + `, ` + "`macaroon`" + `)
- ` + "`previous_key_id`" + ` — ID of the key being replaced during rotation
- ` + "`import_source`" + ` — Origin of an imported API key

`)
}

func printUsageExample() {
	fmt.Print(`## Emitting events

Events are constructed using the fluent builder pattern:

` + "```go" + `
emitter := events.NewOTELEmitter()
events.New(events.EventIssuedAPIKeyCreated).
    WithNetworkID(networkID).
    WithKeyID(keyID).
    WithPrefix("talos").
    WithActor(actorID).
    Emit(ctx, emitter)
` + "```" + `

Events are attached to the active OpenTelemetry span. If no span is recording, the event is
silently dropped.
`)
}
