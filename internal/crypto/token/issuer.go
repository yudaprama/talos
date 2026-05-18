package token

import (
	"slices"

	"github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Covered by TestVerifyJWTWithKeySetAndIssuer and TestVerifyMacaroonWithKeySetAndIssuer
// which exercise matchIssuer via the standalone verify functions.

// matchIssuer checks that the token's issuer claim matches one of the allowed issuers.
// It sets tracing attributes for the issuer and returns an error if the issuer
// is missing or does not match any allowed value.
func matchIssuer(claims *Claims, allowedIssuers []string, span trace.Span) error {
	tokenIssuer, ok := claims.Issuer()
	if !ok || tokenIssuer == "" {
		return errors.New("token missing required issuer claim")
	}

	if slices.Contains(allowedIssuers, tokenIssuer) {
		span.SetAttributes(
			attribute.String("token_issuer", tokenIssuer),
			attribute.Bool("issuer_valid", true),
		)
		return nil
	}

	return errors.Errorf("token issuer mismatch: got %q, allowed %v", tokenIssuer, allowedIssuers)
}

// matchIssuerString checks that a raw issuer string matches one of the allowed issuers.
// Used by verifyCaveat where claims are parsed from raw JSON rather than a *Claims object.
func matchIssuerString(issuer string, allowedIssuers []string) error {
	if issuer == "" {
		return errors.New("caveat missing required issuer claim")
	}
	if slices.Contains(allowedIssuers, issuer) {
		return nil
	}
	return errors.Errorf("issuer mismatch: got %q, allowed %v", issuer, allowedIssuers)
}

// reviewed - @aeneasr - 2026-03-25
