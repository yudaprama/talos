package service_test

import (
	"testing"

	"github.com/ory-corp/talos/internal/service"
	"github.com/ory-corp/talos/internal/verifier"
)

// newTestAdmin creates a Admin and its Verifier backed by file-based SQLite.
// The two share the same signing keys so tokens issued by one can be verified by the other.
// Cleanup is registered via t.Cleanup.
func newTestAdmin(t *testing.T) (*service.Admin, *verifier.Verifier) {
	t.Helper()
	cp, dpv, _ := setupTestService(t)
	return cp, dpv
}

// newTestAdminWithPublicPrefix creates a Admin configured with the given public key
// prefix. Cleanup is registered via t.Cleanup.
func newTestAdminWithPublicPrefix(t *testing.T) (*service.Admin, *verifier.Verifier) {
	t.Helper()
	cp, _ := setupTestAdminWithPublicPrefix(t, "pk_test")
	return cp, cp.Verifier()
}
