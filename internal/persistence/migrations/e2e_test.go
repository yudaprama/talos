package migrations_test

import (
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"

	persistencetypes "github.com/ory/talos/internal/persistence/types"
	"github.com/ory/talos/internal/testutil"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// TestPostgresMigrationRoundTrip proves the PostgreSQL migrations produce a
// working schema: it runs all up migrations into an isolated schema (via
// testutil.InitDriver) and exercises a create/read round-trip through the
// driver. Skipped automatically when TALOS_TEST_DATABASE_URL is unset.
func TestPostgresMigrationRoundTrip(t *testing.T) {
	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)

	ctx := t.Context()

	keyID := uuid.Must(uuid.NewV4()).String()
	created, err := driver.CreateIssuedAPIKey(ctx, persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:        keyID,
		Name:         "round-trip",
		TokenPrefix:  "rt",
		ActorID:      "actor-1",
		Scopes:       json.RawMessage(`["read","write"]`),
		Metadata:     json.RawMessage(`{"team":"core"}`),
		AllowedCIDRs: json.RawMessage(`[]`),
		Visibility:   int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_SECRET),
	})
	require.NoError(t, err)
	require.Equal(t, keyID, created.KeyID)

	got, err := driver.GetIssuedAPIKey(ctx, keyID)
	require.NoError(t, err)
	require.Equal(t, keyID, got.KeyID)
	require.Equal(t, "round-trip", got.Name)
	require.Equal(t, int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE), got.Status)
	require.JSONEq(t, `["read","write"]`, string(got.Scopes))

	active, err := driver.GetActiveIssuedAPIKey(ctx, keyID)
	require.NoError(t, err)
	require.Equal(t, keyID, active.KeyID)
}
