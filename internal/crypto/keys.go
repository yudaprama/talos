// Package crypto provides cryptographic primitives for Talos API key issuance,
// verification, hashing, and signing.
package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/cockroachdb/errors"
	"github.com/gofrs/uuid"
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory-corp/talos/internal/tracing"

	"github.com/ory/x/otelx"
)

// apiKeyRegex matches the format: prefix_v1_identifier_checksum
// - prefix: 1-16 characters (alphanumeric + underscore)
// - version: "v1" literal
// - identifier: timestamp + uuid
// - checksum: 10-11 characters (base58)
var apiKeyRegex = regexp.MustCompile(`^([a-zA-Z0-9_]{1,16})_v1_([1-9A-HJ-NP-Za-km-z]{20,})_([1-9A-HJ-NP-Za-km-z]{10,})$`)

// DecodeIdentifier decodes the base58 key component to timestamp and uuid.
// Guards against adversarial inputs with length limits before decoding.
func DecodeIdentifier(identifier string) (timestamp int64, uuidStr string, err error) {
	if len(identifier) == 0 || len(identifier) > 128 {
		return 0, "", errors.Errorf("identifier length %d outside valid range [1, 128]", len(identifier))
	}

	decoded := base58.Decode(identifier)
	if len(decoded) < 20 || len(decoded) > 60 {
		return 0, "", errors.Errorf("decoded identifier length %d outside valid range [20, 60]", len(decoded))
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return 0, "", errors.Errorf("invalid identifier format: expected 'timestamp:uuid'")
	}

	timestamp, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", errors.Wrap(err, "parse timestamp from identifier")
	}

	// Decode UUID (last 16 bytes)
	id, err := uuid.FromString(parts[1])
	if err != nil {
		return 0, "", errors.Wrap(err, "decode UUID from identifier")
	}

	return timestamp, id.String(), nil
}

// GenerateKeyID generates a new UUID v4 for key identification.
func GenerateKeyID() string {
	return uuid.Must(uuid.NewV4()).String()
}

// KeyComponents holds the parsed components of a generated API key
type KeyComponents struct {
	TokenPrefix string
	Version     string
	KeyID       string // UUID v4 string (36 chars with hyphens) - for DB lookup
	Timestamp   int64  // Unix epoch seconds (embedded in identifier)
	Checksum    string
	Payload     string // The full payload used for HMAC (prefix + version + identifier)
}

// GenerateAPIKey generates an API key in the format: <prefix>_v1_<identifier>_<checksum>.
// The identifier is a base58-encoded timestamp+UUID pair, and the checksum is
// HMAC-SHA256 over the payload, making the timestamp tamper-proof.
func GenerateAPIKey(ctx context.Context, prefix string, hmacSecret []byte) (
	fullKey string,
	keyID string,
	err error,
) {
	_, span := tracing.StartWithoutNID(
		ctx, "crypto.GenerateAPIKey",
		attribute.String("prefix", prefix),
	)
	defer otelx.End(span, &err)

	// 1. Validate prefix (1-16 characters)
	if len(prefix) < 1 || len(prefix) > 16 {
		return "", "", errors.Errorf("prefix must be 1-16 characters, got %d", len(prefix))
	}

	// 2. Generate UUID v4 as key ID (stored in database)
	keyID = GenerateKeyID()
	timestamp := time.Now().UTC().Unix()

	encodedKeyID := base58.Encode(fmt.Appendf(nil, "%v:%s", timestamp, keyID))

	// 5. Construct payload (prefix + version + identifier)
	payload := fmt.Sprintf("%s_v1_%s_", prefix, encodedKeyID)

	h := hmac.New(sha256.New, hmacSecret)
	h.Write([]byte(payload))
	signature := base58.Encode(h.Sum(nil))

	fullKey = payload + signature

	span.SetAttributes(
		attribute.String("key_id", keyID),
		attribute.Int("key_length", len(fullKey)),
		attribute.Int64("timestamp", timestamp),
	)

	return fullKey, keyID, nil
}

// parseAPIKey parses a key string into its components (prefix, version, key ID, timestamp, checksum).
// Format: prefix_v1_identifier_checksum.
// Unexported because callers should use VerifyAPIKeyChecksum which validates the checksum.
func parseAPIKey(key string) (*KeyComponents, error) {
	matches := apiKeyRegex.FindStringSubmatch(key)
	if matches == nil {
		return nil, errors.Errorf("invalid API key format: expected <prefix>_v1_<identifier>_<checksum>")
	}

	// Extract capture groups: [full_match, prefix, identifier, checksum]
	prefix := matches[1]
	identifier := matches[2]
	checksum := matches[3]

	// Decode identifier to get timestamp and UUID
	timestamp, keyID, err := DecodeIdentifier(identifier)
	if err != nil {
		return nil, errors.Wrap(err, "invalid identifier encoding")
	}

	return &KeyComponents{
		TokenPrefix: prefix,
		Version:     "v1",
		KeyID:       keyID,
		Timestamp:   timestamp,
		Checksum:    checksum,
		Payload:     prefix + "_v1_" + identifier + "_", // The payload used for HMAC verification (prefix + identifier)
	}, nil
}

// VerifyAPIKeyChecksum parses and verifies the HMAC checksum of an API key.
// Returns the parsed components if ANY secret produces a valid checksum (supports rotation).
// Secrets are tried in order: current first, then retired.
func VerifyAPIKeyChecksum(key string, hmacSecrets [][]byte) (*KeyComponents, error) {
	components, err := parseAPIKey(key)
	if err != nil {
		return nil, errors.Wrap(err, "parse API key")
	}

	for _, secret := range hmacSecrets {
		h := hmac.New(sha256.New, secret)
		h.Write([]byte(components.Payload))
		expected := base58.Encode(h.Sum(nil))

		if hmac.Equal([]byte(expected), []byte(components.Checksum)) {
			return components, nil
		}
	}

	return nil, errors.New("invalid API key checksum: no secret matched")
}
