// Package verifier provides token verification functionality using KeyService.
package verifier

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"

	internalcrypto "github.com/ory-corp/talos/internal/crypto"
	"github.com/ory-corp/talos/internal/crypto/token"
	"github.com/ory-corp/talos/internal/errdef"
)

// Verifier handles token verification.
// JWT verification uses KeyService for asymmetric key material; macaroon
// verification is symmetric and takes HMAC secrets at the call site, so the
// verifier never dereferences private JWT key material for macaroons.
type Verifier struct {
	keyService *internalcrypto.KeyService
}

// NewVerifier creates a new Verifier.
func NewVerifier(keyService *internalcrypto.KeyService) *Verifier {
	return &Verifier{
		keyService: keyService,
	}
}

// VerifyJWT verifies a JWT token using keys from KeyService and validates issuer.
// allowedIssuers is the list of accepted issuer URLs (current + retired).
func (v *Verifier) VerifyJWT(ctx context.Context, tokenString string, allowedIssuers []string) (*token.Claims, error) {
	keySet, err := v.keyService.ListActiveSigningKeys(ctx)
	if err != nil {
		return nil, errdef.ErrServiceUnavailable().WithReasonf("get signing keys").WithWrap(errors.WithStack(err))
	}

	if keySet.Len() == 0 {
		return nil, errdef.ErrServiceUnavailable().WithReasonf("no active signing keys available")
	}

	return token.VerifyJWTWithKeySetAndIssuer(ctx, tokenString, keySet, allowedIssuers)
}

// VerifyMacaroon verifies a macaroon token using the provided HMAC secrets
// and validates issuer and prefix.
// hmacSecrets must contain the current secret first followed by any retired
// secrets; verification stops at the first match.
// allowedIssuers is the list of accepted issuer URLs (current + retired).
// allowedPrefixes lists the prefixes to try stripping (e.g. ["mc", "auth"]).
func (v *Verifier) VerifyMacaroon(ctx context.Context, tokenString string, hmacSecrets [][]byte, allowedIssuers []string, allowedPrefixes []string, clockSkew time.Duration) (*token.Claims, error) {
	if len(hmacSecrets) == 0 {
		return nil, errdef.ErrServiceUnavailable().WithReasonf("no HMAC secrets configured for macaroon verification")
	}

	return token.VerifyMacaroonWithSecrets(ctx, tokenString, hmacSecrets, allowedIssuers, allowedPrefixes, clockSkew)
}

// reviewed - @aeneasr - 2026-03-26
