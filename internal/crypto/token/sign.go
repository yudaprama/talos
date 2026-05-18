package token

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"

	"github.com/ory-corp/talos/internal/errdef"
)

// SignDerivedTokenParams groups the parameters required for signing a derived token.
type SignDerivedTokenParams struct {
	Algorithm      string // "jwt" or "macaroon"
	Claims         *Claims
	KID            string // JWK key ID (JWT only)
	PrivateKey     any    // JWT only
	HMACSecret     []byte // Macaroon only — shared HMAC secret for root-key derivation
	Issuer         string
	MacaroonPrefix string // only used when algorithm is "macaroon"
}

// SignDerivedToken signs a derived token using the specified algorithm and key material.
// For JWT tokens the JWA algorithm is inferred from the private key type.
func SignDerivedToken(ctx context.Context, p SignDerivedTokenParams) (string, error) {
	switch p.Algorithm {
	case "jwt":
		jwtSigner, err := NewJWTSigner(p.PrivateKey, p.KID)
		if err != nil {
			return "", errdef.InternalError("create JWT signer").WithWrap(errors.WithStack(err))
		}
		tokenString, err := jwtSigner.Sign(ctx, p.Claims)
		if err != nil {
			return "", errdef.InternalError("sign JWT token").WithWrap(errors.WithStack(err))
		}
		return tokenString, nil
	case "macaroon":
		macaroonSigner, err := NewMacaroonSigner(p.HMACSecret, p.Issuer, p.MacaroonPrefix)
		if err != nil {
			return "", errdef.InternalError("create Macaroon signer").WithWrap(errors.WithStack(err))
		}
		tokenString, err := macaroonSigner.Sign(ctx, p.Claims)
		if err != nil {
			return "", errdef.InternalError("sign Macaroon token").WithWrap(errors.WithStack(err))
		}
		return tokenString, nil
	default:
		return "", errdef.BadRequest(fmt.Sprintf("unsupported algorithm: %s", p.Algorithm))
	}
}
