// Package token provides JWT and macaroon token signing and verification.
package token

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"

	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory-corp/talos/internal/tracing"

	"github.com/ory/x/otelx"
)

// verifyJWTWithKeySet verifies a JWT token against a JWK key set and returns claims.
func verifyJWTWithKeySet(ctx context.Context, tokenString string, keySet jwk.Set) (claims *Claims, err error) {
	_, span := tracing.StartWithoutNID(ctx, "jwt.VerifyWithKeySet")
	defer otelx.End(span, &err)

	parsedToken, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keySet), jwt.WithValidate(true))
	if err != nil {
		return nil, errors.Wrap(err, "parse/verify JWT token")
	}

	claims, err = fromJWXToken(parsedToken)
	if err != nil {
		return nil, err
	}

	span.SetAttributes(
		attribute.String("token_type", string(claims.tokenType)),
	)

	return claims, nil
}

// VerifyJWTWithKeySetAndIssuer verifies a JWT token against a JWK key set, validates issuer, and returns claims.
// allowedIssuers is the list of accepted issuer URLs (current + retired).
func VerifyJWTWithKeySetAndIssuer(ctx context.Context, tokenString string, keySet jwk.Set, allowedIssuers []string) (claims *Claims, err error) {
	_, span := tracing.StartWithoutNID(ctx, "jwt.VerifyWithKeySetAndIssuer")
	defer otelx.End(span, &err)

	// First verify signature with key set
	claims, err = verifyJWTWithKeySet(ctx, tokenString, keySet)
	if err != nil {
		return nil, err
	}

	// Validate issuer claim against allowed issuers
	if err = matchIssuer(claims, allowedIssuers, span); err != nil {
		return nil, err
	}

	return claims, nil
}

// JWTAlgorithm represents the JWT signing algorithm
type JWTAlgorithm string

// JWT algorithm constants
const (
	JWTAlgorithmEdDSA JWTAlgorithm = "EdDSA"
	JWTAlgorithmRS256 JWTAlgorithm = "RS256"
)

// JWTSigner implements the Signer interface for JWT tokens
type JWTSigner struct {
	algorithm  JWTAlgorithm
	privateKey any
	publicKey  crypto.PublicKey
	kid        string
	sigAlg     jwa.SignatureAlgorithm
}

// NewJWTSigner creates a new JWT signer with the JWA algorithm inferred from
// the key type (ed25519.PrivateKey → EdDSA, *rsa.PrivateKey → RS256).
func NewJWTSigner(privateKey any, kid string) (*JWTSigner, error) {
	var (
		algorithm JWTAlgorithm
		sigAlg    jwa.SignatureAlgorithm
		publicKey crypto.PublicKey
	)

	switch priv := privateKey.(type) {
	case ed25519.PrivateKey:
		algorithm = JWTAlgorithmEdDSA
		sigAlg = jwa.EdDSA()
		publicKey = priv.Public()

	case *rsa.PrivateKey:
		algorithm = JWTAlgorithmRS256
		sigAlg = jwa.RS256()
		publicKey = &priv.PublicKey

	default:
		return nil, errors.Errorf("unsupported private key type %T (want ed25519.PrivateKey or *rsa.PrivateKey)", privateKey)
	}

	return &JWTSigner{
		algorithm:  algorithm,
		privateKey: privateKey,
		publicKey:  publicKey,
		kid:        kid,
		sigAlg:     sigAlg,
	}, nil
}

// Algorithm returns the algorithm identifier
func (s *JWTSigner) Algorithm() Algorithm {
	return AlgorithmJWT
}

// Sign creates a JWT token with the given claims
func (s *JWTSigner) Sign(ctx context.Context, claims *Claims) (tokenString string, err error) {
	_, span := tracing.StartWithoutNID(
		ctx, "jwt.Sign",
		attribute.String("algorithm", string(s.algorithm)),
		attribute.String("token_type", string(claims.tokenType)),
	)
	defer otelx.End(span, &err)

	// Build JWT token from claims via JSON round-trip.
	// Claims MarshalJSON uses standard JWT claim names; jwx handles RFC3339→NumericDate.
	// NOTE: NID is intentionally NOT stored in JWT claims.
	// Network ID must always come from context (set by middleware).
	token, err := claims.toJWTToken()
	if err != nil {
		return "", errors.Wrap(err, "build JWT token")
	}

	// Sign the token
	// Wrap private key in JWK to set Key ID
	key, err := jwk.Import(s.privateKey)
	if err != nil {
		return "", errors.Wrap(err, "create JWK from private key")
	}
	if err := key.Set(jwk.KeyIDKey, s.kid); err != nil {
		return "", errors.Wrap(err, "set key ID on JWK")
	}
	// Also set algorithm on key to ensure consistency
	if err := key.Set(jwk.AlgorithmKey, s.sigAlg); err != nil {
		return "", errors.Wrap(err, "set algorithm on JWK")
	}

	signedBytes, err := jwt.Sign(token, jwt.WithKey(s.sigAlg, key))
	if err != nil {
		return "", errors.Wrap(err, "sign JWT token")
	}

	return string(signedBytes), nil
}

// PublicKey returns the public key for this signer
func (s *JWTSigner) PublicKey() (crypto.PublicKey, error) {
	return s.publicKey, nil
}

// KeyID returns the key identifier
func (s *JWTSigner) KeyID() string {
	return s.kid
}

// toJWTToken converts Claims to a jwt.Token via JSON round-trip.
// The Claims JSON tags use standard JWT claim names, and jwx's
// Token.UnmarshalJSON handles RFC3339 time strings via NumericDate.Accept().
func (c *Claims) toJWTToken() (jwt.Token, error) {
	t := jwt.New()
	data, err := json.Marshal(c)
	if err != nil {
		return nil, errors.Wrap(err, "marshal claims")
	}
	if err := json.Unmarshal(data, t); err != nil {
		return nil, errors.Wrap(err, "populate jwt token")
	}
	return t, nil
}

// fromJWXToken converts a jwx Token to our Claims.
// Standard claims use typed accessors; custom claims are extracted via Keys() + Get().
func fromJWXToken(t jwt.Token) (*Claims, error) {
	jwtID, _ := t.JwtID()
	sub, _ := t.Subject()
	iss, _ := t.Issuer()
	aud, _ := t.Audience()
	iat, _ := t.IssuedAt()
	exp, _ := t.Expiration()
	nbf, _ := t.NotBefore()

	claims := &Claims{
		tokenID:   jwtID,
		subject:   sub,
		issuer:    iss,
		audience:  aud,
		issuedAt:  iat,
		expiresAt: exp,
		notBefore: nbf,
	}

	// Extract custom claims using Keys() + Get().
	// Standard JWT keys are already handled above, so we only process non-standard ones.
	// NOTE: NID is intentionally NOT extracted from tokens.
	// Network ID must always come from context (set by middleware).
	standardKeys := map[string]bool{
		jwt.JwtIDKey: true, jwt.SubjectKey: true, jwt.IssuerKey: true,
		jwt.AudienceKey: true, jwt.IssuedAtKey: true, jwt.ExpirationKey: true,
		jwt.NotBeforeKey: true,
	}
	for _, key := range t.Keys() {
		if standardKeys[key] {
			continue
		}
		var val any
		if err := t.Get(key, &val); err != nil {
			return nil, errors.Wrapf(err, "get private claim %s", key)
		}
		if err := claims.Set(key, val); err != nil {
			return nil, errors.Wrapf(err, "set private claim %s", key)
		}
	}

	if claims.metadata == nil {
		claims.metadata = make(map[string]any)
	}

	return claims, nil
}

// reviewed - @aeneasr - 2026-03-25
