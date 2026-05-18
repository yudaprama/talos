package persistencetest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/persistence"
)

// methodsCoveredExternally lists Persister methods that are exercised outside
// the persistencetest package and therefore won't appear in the AST scan
// below. The driver constructor (`testkit.SetupSQLiteDriver`,
// `commercial/testkit.SetupPostgresDriver`, …) calls Close via t.Cleanup and
// reports DriverName at construction time, so the shared suite never invokes
// either directly. New entries here should be the exception, not the norm.
//
//nolint:gochecknoglobals // Static, read-only list of externally-covered methods.
var methodsCoveredExternally = map[string]string{
	"Close":      "driver constructor t.Cleanup closes the driver",
	"DriverName": "verified at driver construction in testkit",
}

// TestPersisterMethodCoverage enumerates the methods on persistence.Persister
// via reflection and asserts every method either has a call site in this
// package (detected by AST walk over s.driver/driver method calls) or is
// listed in methodsCoveredExternally. Adding a new method to the interface
// without a call site fails the test until the developer wires up coverage.
//
// The inverse direction is also checked: a name in
// methodsCoveredExternally that no longer matches an interface method is a
// stale entry and fails the test.
func TestPersisterMethodCoverage(t *testing.T) {
	t.Parallel()

	methods := persisterMethodNames()
	called := collectCalledPersisterMethods(t)

	missing := make([]string, 0)
	for _, name := range methods {
		if _, ok := called[name]; ok {
			continue
		}
		if _, ok := methodsCoveredExternally[name]; ok {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	assert.Empty(t, missing,
		"Persister methods missing call sites in persistencetest (and not listed in methodsCoveredExternally): %v",
		missing)

	// Inverse: every entry in methodsCoveredExternally must still match an
	// interface method, or it is stale and should be removed.
	want := make(map[string]struct{}, len(methods))
	for _, name := range methods {
		want[name] = struct{}{}
	}
	stale := make([]string, 0)
	for name := range methodsCoveredExternally {
		if _, ok := want[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"methodsCoveredExternally entries refer to methods no longer on Persister: %v — remove the stale entries",
		stale)
}

// persisterMethodNames returns the sorted method names on the
// persistence.Persister interface using reflection.
func persisterMethodNames() []string {
	iface := reflect.TypeFor[persistence.Persister]()
	out := make([]string, 0, iface.NumMethod())
	for method := range iface.Methods() {
		out = append(out, method.Name)
	}
	sort.Strings(out)
	return out
}

// collectCalledPersisterMethods parses every *.go file in the
// persistencetest package and returns the set of selector names called on a
// `driver`-shaped receiver, capturing patterns like:
//
//	s.driver.Foo(...)
//	driver.Foo(...)
//	s.driver.Bar(...).Baz(...) // both Foo and Bar are recorded
func collectCalledPersisterMethods(t *testing.T) map[string]struct{} {
	t.Helper()
	fset := token.NewFileSet()
	// We deliberately scan every file regardless of build tags so commercial-only
	// suite extensions count toward coverage; ParseDir is the simplest way to
	// pick up the entire package on disk.
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.SkipObjectResolution) //nolint:staticcheck // SA1019: ParseDir is fine here; we want all files regardless of build tags.
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)

	called := make(map[string]struct{})
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if isDriverSelector(sel.X) {
					called[sel.Sel.Name] = struct{}{}
				}
				return true
			})
		}
	}
	return called
}

// isDriverSelector reports whether expr resolves to a driver-shaped receiver:
// either an identifier literally named `driver`, or a selector ending in
// `.driver` (most commonly `s.driver` from suite methods).
func isDriverSelector(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "driver"
	case *ast.SelectorExpr:
		return e.Sel != nil && e.Sel.Name == "driver"
	}
	return false
}
