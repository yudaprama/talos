package token

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaims_NetworkID_GetterSetter(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// Initially empty
	assert.Empty(t, claims.GetNetworkID())

	// Set and verify
	claims.SetNetworkID("network-123")
	assert.Equal(t, "network-123", claims.GetNetworkID())

	// Update and verify
	claims.SetNetworkID("network-456")
	assert.Equal(t, "network-456", claims.GetNetworkID())
}

func TestClaims_NetworkID_Has(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// Initially not present
	assert.False(t, claims.Has(claimKeyNetworkID))

	// Present after setting
	claims.SetNetworkID("network-123")
	assert.True(t, claims.Has(claimKeyNetworkID))
}

func TestClaims_NetworkID_Get(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetNetworkID("network-123")

	var nid string
	err := claims.Get(claimKeyNetworkID, &nid)
	require.NoError(t, err)
	assert.Equal(t, "network-123", nid)
}

func TestClaims_NetworkID_Set(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// Set via generic interface
	err := claims.Set(claimKeyNetworkID, "network-123")
	require.NoError(t, err)
	assert.Equal(t, "network-123", claims.GetNetworkID())

	// Type validation - should fail for non-string
	err = claims.Set(claimKeyNetworkID, 123)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected string")
}

func TestClaims_NetworkID_Remove(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetNetworkID("network-123")

	// Remove
	err := claims.Remove(claimKeyNetworkID)
	require.NoError(t, err)
	assert.Empty(t, claims.GetNetworkID())
	assert.False(t, claims.Has(claimKeyNetworkID))
}

func TestClaims_NetworkID_Keys(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// Keys should not include NID when empty
	keys := claims.Keys()
	assert.NotContains(t, keys, claimKeyNetworkID)

	// Keys should include NID when set
	claims.SetNetworkID("network-123")
	keys = claims.Keys()
	assert.Contains(t, keys, claimKeyNetworkID)
}

func TestClaims_NetworkID_PrivateClaims(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// PrivateClaims should not include NID when empty
	privateClaims := claims.PrivateClaims()
	_, ok := privateClaims[claimKeyNetworkID]
	assert.False(t, ok)

	// PrivateClaims should include NID when set
	claims.SetNetworkID("network-123")
	privateClaims = claims.PrivateClaims()
	nid, ok := privateClaims[claimKeyNetworkID]
	assert.True(t, ok)
	assert.Equal(t, "network-123", nid)
}

func TestClaims_NetworkID_Clone(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetNetworkID("network-123")

	// Clone should copy NID
	cloned, err := claims.Clone()
	require.NoError(t, err)

	clonedClaims, ok := cloned.(*Claims)
	require.True(t, ok)
	assert.Equal(t, "network-123", clonedClaims.GetNetworkID())

	// Modifying clone should not affect original
	clonedClaims.SetNetworkID("network-456")
	assert.Equal(t, "network-123", claims.GetNetworkID())
	assert.Equal(t, "network-456", clonedClaims.GetNetworkID())
}

func TestClaims_NetworkID_MarshalJSON(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetTokenID("token-123")
	claims.SetNetworkID("network-123")

	// Marshal to JSON
	data, err := json.Marshal(claims)
	require.NoError(t, err)

	// Should contain NID with correct key
	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Equal(t, "network-123", raw[claimKeyNetworkID])
	assert.Equal(t, "token-123", raw["jti"])
}

func TestClaims_NetworkID_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"jti": "token-123",
		"nid": "network-123",
		"tty": "derived"
	}`

	claims := &Claims{}
	err := json.Unmarshal([]byte(jsonData), claims)
	require.NoError(t, err)

	assert.Equal(t, "network-123", claims.GetNetworkID())
	assert.Equal(t, "token-123", claims.tokenID)
	assert.Equal(t, TokenTypeDerived, claims.tokenType)
}

func TestClaims_NetworkID_MarshalUnmarshalRoundtrip(t *testing.T) {
	t.Parallel()

	original := NewClaims()
	original.SetTokenID("token-123")
	original.SetNetworkID("network-123")
	original.SetTokenType(TokenTypeDerived)
	original.SetScopes([]string{"read", "write"})

	// Marshal
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal
	restored := &Claims{}
	err = json.Unmarshal(data, restored)
	require.NoError(t, err)

	// Verify fields that survive round-trip (tokenType is not serialized)
	assert.Equal(t, original.GetNetworkID(), restored.GetNetworkID())
	assert.Equal(t, original.tokenID, restored.tokenID)
	assert.Equal(t, original.GetScopes(), restored.GetScopes())
}

func TestClaims_NetworkID_EmptyNotSerialized(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetTokenID("token-123")
	// Do not set NetworkID

	// Marshal to JSON
	data, err := json.Marshal(claims)
	require.NoError(t, err)

	// Should not contain NID key
	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, ok := raw[claimKeyNetworkID]
	assert.False(t, ok, "empty NID should not be serialized")
}

func TestClaims_Scopes_MarshalJSON_UsesCanonicalClaimKey(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetScopes([]string{"read", "write"})

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Equal(t, []any{"read", "write"}, raw[claimKeyScopes])
	_, ok := raw[claimKeyScopesAlias]
	assert.False(t, ok, "legacy scopes alias should not be serialized")
}

func TestClaims_Scopes_UnmarshalJSON_AcceptsLegacyAlias(t *testing.T) {
	t.Parallel()

	claims := &Claims{}
	err := json.Unmarshal([]byte(`{"scope":["read","write"]}`), claims)
	require.NoError(t, err)

	assert.Equal(t, []string{"read", "write"}, claims.GetScopes())
}

func TestClaims_Scopes_UnmarshalJSON_PrefersCanonicalClaimKey(t *testing.T) {
	t.Parallel()

	claims := &Claims{}
	err := json.Unmarshal([]byte(`{"scp":["read"],"scope":["write"]}`), claims)
	require.NoError(t, err)

	assert.Equal(t, []string{"read"}, claims.GetScopes())
}

func TestClaims_Visibility_GetterSetter(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// Initially empty
	assert.Empty(t, claims.GetVisibility())

	// Set and verify
	claims.SetVisibility("public")
	assert.Equal(t, "public", claims.GetVisibility())

	// Update and verify
	claims.SetVisibility("secret")
	assert.Equal(t, "secret", claims.GetVisibility())
}

func TestClaims_Visibility_Has(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// Initially not present
	assert.False(t, claims.Has(claimKeyVisibility))

	// Present after setting
	claims.SetVisibility("public")
	assert.True(t, claims.Has(claimKeyVisibility))
}

func TestClaims_Visibility_Get(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetVisibility("public")

	var vis string
	err := claims.Get(claimKeyVisibility, &vis)
	require.NoError(t, err)
	assert.Equal(t, "public", vis)
}

func TestClaims_Visibility_Set(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// Set via generic interface
	err := claims.Set(claimKeyVisibility, "secret")
	require.NoError(t, err)
	assert.Equal(t, "secret", claims.GetVisibility())

	// Type validation - should fail for non-string
	err = claims.Set(claimKeyVisibility, 123)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected string")
}

func TestClaims_Visibility_Remove(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetVisibility("public")

	// Remove
	err := claims.Remove(claimKeyVisibility)
	require.NoError(t, err)
	assert.Empty(t, claims.GetVisibility())
	assert.False(t, claims.Has(claimKeyVisibility))
}

func TestClaims_Visibility_Keys(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// Keys should not include vis when empty
	keys := claims.Keys()
	assert.NotContains(t, keys, claimKeyVisibility)

	// Keys should include vis when set
	claims.SetVisibility("public")
	keys = claims.Keys()
	assert.Contains(t, keys, claimKeyVisibility)
}

func TestClaims_Visibility_PrivateClaims(t *testing.T) {
	t.Parallel()

	claims := NewClaims()

	// PrivateClaims should not include vis when empty
	privateClaims := claims.PrivateClaims()
	_, ok := privateClaims[claimKeyVisibility]
	assert.False(t, ok)

	// PrivateClaims should include vis when set
	claims.SetVisibility("public")
	privateClaims = claims.PrivateClaims()
	vis, ok := privateClaims[claimKeyVisibility]
	assert.True(t, ok)
	assert.Equal(t, "public", vis)
}

func TestClaims_Visibility_Clone(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetVisibility("public")

	// Clone should copy visibility
	cloned, err := claims.Clone()
	require.NoError(t, err)

	clonedClaims, ok := cloned.(*Claims)
	require.True(t, ok)
	assert.Equal(t, "public", clonedClaims.GetVisibility())

	// Modifying clone should not affect original
	clonedClaims.SetVisibility("secret")
	assert.Equal(t, "public", claims.GetVisibility())
	assert.Equal(t, "secret", clonedClaims.GetVisibility())
}

func TestClaims_Visibility_MarshalJSON(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetTokenID("token-123")
	claims.SetVisibility("public")

	// Marshal to JSON
	data, err := json.Marshal(claims)
	require.NoError(t, err)

	// Should contain vis with correct key
	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Equal(t, "public", raw[claimKeyVisibility])
	assert.Equal(t, "token-123", raw["jti"])
}

func TestClaims_Visibility_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"jti": "token-123",
		"vis": "secret",
		"tty": "derived"
	}`

	claims := &Claims{}
	err := json.Unmarshal([]byte(jsonData), claims)
	require.NoError(t, err)

	assert.Equal(t, "secret", claims.GetVisibility())
	assert.Equal(t, "token-123", claims.tokenID)
	assert.Equal(t, TokenTypeDerived, claims.tokenType)
}

func TestClaims_Visibility_EmptyNotSerialized(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetTokenID("token-123")
	// Do not set Visibility

	// Marshal to JSON
	data, err := json.Marshal(claims)
	require.NoError(t, err)

	// Should not contain vis key
	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, ok := raw[claimKeyVisibility]
	assert.False(t, ok, "empty visibility should not be serialized")
}

func TestClaims_Visibility_MarshalUnmarshalRoundtrip(t *testing.T) {
	t.Parallel()

	original := NewClaims()
	original.SetTokenID("token-123")
	original.SetVisibility("public")
	original.SetNetworkID("network-123")

	// Marshal
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal
	restored := &Claims{}
	err = json.Unmarshal(data, restored)
	require.NoError(t, err)

	// Verify round-trip
	assert.Equal(t, original.GetVisibility(), restored.GetVisibility())
	assert.Equal(t, original.tokenID, restored.tokenID)
	assert.Equal(t, original.GetNetworkID(), restored.GetNetworkID())
}

func TestClaims_CustomClaims_DoNotOverrideReservedAllowedCIDRs(t *testing.T) {
	t.Parallel()

	claims := NewClaims()
	claims.SetAllowedCidrs([]string{"192.168.1.0/24"})
	claims.SetCustomClaims(map[string]any{
		claimKeyAllowedCidrs: []any{"10.0.0.0/8"},
		"tenant":             "alpha",
	})

	data, err := json.Marshal(claims)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Equal(t, []any{"192.168.1.0/24"}, raw[claimKeyAllowedCidrs])
	assert.Equal(t, "alpha", raw["tenant"])
}

// reviewed - @aeneasr - 2026-03-25
