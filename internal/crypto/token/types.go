package token

import (
	"context"
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Algorithm represents a token signing algorithm
type Algorithm string

// Token algorithm constants
const (
	AlgorithmJWT      Algorithm = "jwt"      // JWT with RS256 or EdDSA (self-contained, signed)
	AlgorithmMacaroon Algorithm = "macaroon" // Macaroon (HMAC-based, with caveats)
)

// TokenType represents the type of token.
// Note: Named TokenType (not Type) for clarity when used outside this package.
//
//nolint:revive // Intentional naming for external clarity
type TokenType string

// Token type constants
const (
	TokenTypeIssued  TokenType = "issued"  // Long-lived, stored in DB
	TokenTypeDerived TokenType = "derived" // Short-lived, derived from issued key
)

// Claims represents the claims embedded in a token.
// Implements jwt.Token so it can be passed directly to jwt.Sign/jwt.Parse.
//
// IMPORTANT: Network ID (NID) is stored in claims for defense-in-depth validation.
// The context-derived NID (from hostname middleware) remains the source of truth.
// Token verification validates that claim NID matches context NID to prevent
// cross-tenant token usage.
type Claims struct {
	// Standard claims
	tokenID   string    // jti - unique token ID (UUID)
	subject   string    // sub - actor ID
	issuer    string    // iss - issuer (e.g., "talos-service")
	audience  []string  // aud - intended audience
	issuedAt  time.Time // iat - issued at
	expiresAt time.Time // exp - expiration time
	notBefore time.Time // nbf - not before

	// Custom claims
	tokenType    TokenType      // Type of token (issued or derived)
	keyID        string         // API key ID (maps to 'akid' claim in JWT; distinct from JWT header 'kid' which identifies the signing key)
	parentID     string         // Parent token ID (for session tokens)
	actorID      string         // Actor identifier
	networkID    string         // Network ID (for cross-tenant isolation)
	scopes       []string       // Permissions/scopes
	metadata     map[string]any // Arbitrary metadata (supports strings, arrays, nested objects)
	visibility   string         // Key visibility ("public" or "secret")
	allowedCidrs []string       // Allowed CIDR ranges (inherited from parent key for IP restriction)
	customClaims map[string]any // User-defined top-level JWT claims (cannot override reserved names)

	options jwt.TokenOptionSet // Per-token options for jwt.Token interface
}

var _ jwt.Token = (*Claims)(nil)

// NewClaims creates a new empty Claims instance.
func NewClaims() *Claims {
	return &Claims{}
}

// JwtID returns the token ID (jti claim). Implements jwt.Token.
func (c *Claims) JwtID() (string, bool) { return c.tokenID, c.tokenID != "" }

// Subject returns the subject (sub claim). Implements jwt.Token.
func (c *Claims) Subject() (string, bool) { return c.subject, c.subject != "" }

// Issuer returns the issuer (iss claim). Implements jwt.Token.
func (c *Claims) Issuer() (string, bool) { return c.issuer, c.issuer != "" }

// Audience returns the audience (aud claim). Implements jwt.Token.
func (c *Claims) Audience() ([]string, bool) { return c.audience, c.audience != nil }

// IssuedAt returns the issued-at time (iat claim). Implements jwt.Token.
func (c *Claims) IssuedAt() (time.Time, bool) { return c.issuedAt, !c.issuedAt.IsZero() }

// Expiration returns the expiration time (exp claim). Implements jwt.Token.
func (c *Claims) Expiration() (time.Time, bool) { return c.expiresAt, !c.expiresAt.IsZero() }

// NotBefore returns the not-before time (nbf claim). Implements jwt.Token.
func (c *Claims) NotBefore() (time.Time, bool) { return c.notBefore, !c.notBefore.IsZero() }

// GetTokenType returns the token type (issued or derived).
func (c *Claims) GetTokenType() TokenType { return c.tokenType }

// GetKeyID returns the API key ID. Falls back to subject if not set,
// since session tokens encode the key ID as the JWT subject.
func (c *Claims) GetKeyID() string {
	if c.keyID != "" {
		return c.keyID
	}
	return c.subject
}

// GetParentID returns the parent token ID (for session tokens). Falls back
// to subject if not set, since session tokens encode the parent key ID as the JWT subject.
func (c *Claims) GetParentID() string {
	if c.parentID != "" {
		return c.parentID
	}
	return c.subject
}

// GetActorID returns the actor identifier.
func (c *Claims) GetActorID() string { return c.actorID }

// GetScopes returns the token scopes.
func (c *Claims) GetScopes() []string { return c.scopes }

// GetMetadata returns the token metadata.
func (c *Claims) GetMetadata() map[string]any { return c.metadata }

// GetVisibility returns the key visibility ("public" or "secret").
func (c *Claims) GetVisibility() string { return c.visibility }

// SetVisibility sets the key visibility.
func (c *Claims) SetVisibility(v string) { c.visibility = v }

// GetNetworkID returns the network ID.
func (c *Claims) GetNetworkID() string { return c.networkID }

// SetTokenID sets the token ID (jti claim).
func (c *Claims) SetTokenID(v string) { c.tokenID = v }

// SetSubject sets the subject (sub claim).
func (c *Claims) SetSubject(v string) { c.subject = v }

// SetIssuer sets the issuer (iss claim).
func (c *Claims) SetIssuer(v string) { c.issuer = v }

// SetAudience sets the audience (aud claim).
func (c *Claims) SetAudience(v []string) { c.audience = v }

// SetIssuedAt sets the issued-at time (iat claim).
func (c *Claims) SetIssuedAt(v time.Time) { c.issuedAt = v }

// SetExpiration sets the expiration time (exp claim).
func (c *Claims) SetExpiration(v time.Time) { c.expiresAt = v }

// SetNotBefore sets the not-before time (nbf claim).
func (c *Claims) SetNotBefore(v time.Time) { c.notBefore = v }

// SetTokenType sets the token type.
func (c *Claims) SetTokenType(v TokenType) { c.tokenType = v }

// SetKeyID sets the API key ID.
func (c *Claims) SetKeyID(v string) { c.keyID = v }

// SetParentID sets the parent token ID.
func (c *Claims) SetParentID(v string) { c.parentID = v }

// SetActorID sets the actor identifier.
func (c *Claims) SetActorID(v string) { c.actorID = v }

// SetNetworkID sets the network ID.
func (c *Claims) SetNetworkID(v string) { c.networkID = v }

// SetScopes sets the token scopes.
func (c *Claims) SetScopes(v []string) { c.scopes = v }

// SetMetadata sets the token metadata.
func (c *Claims) SetMetadata(v map[string]any) { c.metadata = v }

// GetAllowedCidrs returns the allowed CIDR ranges.
func (c *Claims) GetAllowedCidrs() []string { return c.allowedCidrs }

// SetAllowedCidrs sets the allowed CIDR ranges.
func (c *Claims) SetAllowedCidrs(v []string) { c.allowedCidrs = v }

// GetCustomClaims returns the user-defined top-level JWT claims.
func (c *Claims) GetCustomClaims() map[string]any { return c.customClaims }

// SetCustomClaims sets user-defined claims that appear as top-level JWT fields.
func (c *Claims) SetCustomClaims(v map[string]any) { c.customClaims = v }

// Signer is the interface that all token algorithms must implement.
// Verification is handled by standalone functions (VerifyJWTWithKeySetAndIssuer,
// VerifyMacaroonWithKeySetAndIssuer) that validate issuer and use key sets.
type Signer interface {
	// Algorithm returns the algorithm identifier
	Algorithm() Algorithm

	// Sign creates a token with the given claims
	Sign(ctx context.Context, _ *Claims) (string, error)

	// PublicKey returns the public key for this signer (for JWKS)
	PublicKey() (crypto.PublicKey, error)

	// KeyID returns the key identifier
	KeyID() string
}

// reviewed - @aeneasr - 2026-03-26
