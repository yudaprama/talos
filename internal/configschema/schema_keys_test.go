package configschema_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/configschema"
)

const schemaTypeObject = "object"

func TestConfigSchemaKeysMatchConstants(t *testing.T) {
	t.Parallel()

	schemaKeys := collectSchemaKeys(t)
	configKeys := collectConfigKeys(t)

	missingInConfig := difference(schemaKeys, configKeys)
	missingInSchema := difference(configKeys, schemaKeys)

	if len(missingInConfig) > 0 || len(missingInSchema) > 0 {
		t.Fatalf("configuration key mismatch: schema-only=%v, config-only=%v", missingInConfig, missingInSchema)
	}
}

func collectSchemaKeys(t *testing.T) map[string]struct{} {
	t.Helper()

	var schema map[string]any
	require.NoError(t, json.Unmarshal(configschema.SchemaJSON, &schema))

	keys := make(map[string]struct{})

	var walk func(map[string]any, string)
	walk = func(node map[string]any, prefix string) {
		props, ok := node["properties"].(map[string]any)
		if !ok {
			return
		}

		for name, raw := range props {
			prop, ok := raw.(map[string]any)
			if !ok {
				continue
			}

			path := name
			if prefix != "" {
				path = prefix + "." + name
			}

			switch extractType(prop) {
			case schemaTypeObject:
				if shouldTrackObject(prop) {
					keys[path] = struct{}{}
				}
				walk(prop, path)
			default:
				keys[path] = struct{}{}
			}
		}
	}

	walk(schema, "")
	return keys
}

func extractType(prop map[string]any) string {
	if prop == nil {
		return ""
	}
	switch v := prop["type"].(type) {
	case string:
		return v
	case []any:
		for _, candidate := range v {
			if s, ok := candidate.(string); ok && s == schemaTypeObject {
				return schemaTypeObject
			}
		}
	}

	if _, ok := prop["properties"]; ok {
		return schemaTypeObject
	}
	return ""
}

func shouldTrackObject(prop map[string]any) bool {
	additional, ok := prop["additionalProperties"]
	if !ok {
		return false
	}

	switch v := additional.(type) {
	case bool:
		return v
	case map[string]any:
		return true
	default:
		return false
	}
}

func collectConfigKeys(t *testing.T) map[string]struct{} {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	keyFile := filepath.Join(repoRoot, "internal", "config", "keys.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, keyFile, nil, parser.ParseComments)
	require.NoError(t, err)

	keys := make(map[string]struct{})

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}

		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok || len(valueSpec.Values) == 0 {
				continue
			}

			for i, expr := range valueSpec.Values {
				cl, ok := expr.(*ast.CompositeLit)
				if !ok {
					continue
				}

				ident, ok := cl.Type.(*ast.Ident)
				if !ok || ident.Name != "Key" {
					continue
				}

				keyName, ok := extractKeyLiteral(cl)
				if !ok {
					continue
				}

				if i < len(valueSpec.Names) && valueSpec.Names[i] != nil {
					keys[keyName] = struct{}{}
				}
			}
		}
	}

	return keys
}

func extractKeyLiteral(cl *ast.CompositeLit) (string, bool) {
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}

		ident, ok := kv.Key.(*ast.Ident)
		if !ok || ident.Name != "s" {
			continue
		}

		lit, ok := kv.Value.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}

		unquoted, err := strconv.Unquote(lit.Value)
		if err != nil {
			return "", false
		}

		return unquoted, true
	}

	return "", false
}

func difference(a, b map[string]struct{}) []string {
	diff := make([]string, 0)
	for k := range a {
		if _, ok := b[k]; !ok {
			diff = append(diff, k)
		}
	}
	slices.Sort(diff)
	return diff
}
