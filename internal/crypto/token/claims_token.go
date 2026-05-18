package token

import (
	"bytes"
	"encoding/json"
	"slices"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Claims uses a map-based storage with typed accessors. While verbose, each
// accessor is trivially correct (item 16 of the verifier-crypto plan rejected
// a field-descriptor refactor because the current approach is repetitive but safe).

// Custom claim keys used in JWT serialization.
const (
	claimKeyTokenType    = "tty"
	claimKeyAPIKeyID     = "akid"
	claimKeyParentID     = "pid"
	claimKeyActorID      = "act"
	claimKeyNetworkID    = "nid"
	claimKeyScopes       = "scp"
	claimKeyScopesAlias  = "scope"
	claimKeyMetadata     = "meta"
	claimKeyVisibility   = "vis"
	claimKeyAllowedCidrs = "acl"
)

// Sentinel errors for claims operations.
var (
	errInvalidClaimType = errors.New("invalid claim type")
	errUnknownClaim     = errors.New("unknown claim")
	errUnsupportedTime  = errors.New("unsupported time type")
)

// Options returns per-token options.
func (c *Claims) Options() *jwt.TokenOptionSet {
	return &c.options
}

// Get retrieves the value of the named claim into dst.
func (c *Claims) Get(name string, dst any) error {
	val, ok := c.getClaim(name)
	if !ok {
		return errors.Wrapf(errUnknownClaim, "%s", name)
	}

	// Assign to dst pointer
	switch d := dst.(type) {
	case *any:
		*d = val
		return nil
	case *string:
		s, ok := val.(string)
		if !ok {
			return errors.Wrapf(errInvalidClaimType, "expected string for %s, got %T", name, val)
		}
		*d = s
		return nil
	case *[]string:
		s, ok := val.([]string)
		if !ok {
			return errors.Wrapf(errInvalidClaimType, "expected []string for %s, got %T", name, val)
		}
		*d = s
		return nil
	case *time.Time:
		t, ok := val.(time.Time)
		if !ok {
			return errors.Wrapf(errInvalidClaimType, "expected time.Time for %s, got %T", name, val)
		}
		*d = t
		return nil
	case *map[string]any:
		m, ok := val.(map[string]any)
		if !ok {
			return errors.Wrapf(errInvalidClaimType, "expected map[string]any for %s, got %T", name, val)
		}
		*d = m
		return nil
	default:
		return errors.Wrapf(errInvalidClaimType, "unsupported destination type %T for claim %s", dst, name)
	}
}

// Has returns true if the named claim has a value set.
func (c *Claims) Has(name string) bool {
	_, ok := c.getClaim(name)
	return ok
}

// Keys returns the names of all claims that have been set.
func (c *Claims) Keys() []string {
	keys := make([]string, 0, 14)
	if c.tokenID != "" {
		keys = append(keys, jwt.JwtIDKey)
	}
	if c.subject != "" {
		keys = append(keys, jwt.SubjectKey)
	}
	if c.issuer != "" {
		keys = append(keys, jwt.IssuerKey)
	}
	if c.audience != nil {
		keys = append(keys, jwt.AudienceKey)
	}
	if !c.issuedAt.IsZero() {
		keys = append(keys, jwt.IssuedAtKey)
	}
	if !c.expiresAt.IsZero() {
		keys = append(keys, jwt.ExpirationKey)
	}
	if !c.notBefore.IsZero() {
		keys = append(keys, jwt.NotBeforeKey)
	}
	if c.actorID != "" {
		keys = append(keys, claimKeyActorID)
	}
	if c.networkID != "" {
		keys = append(keys, claimKeyNetworkID)
	}
	if c.scopes != nil {
		keys = append(keys, claimKeyScopes)
	}
	if c.metadata != nil {
		keys = append(keys, claimKeyMetadata)
	}
	if c.visibility != "" {
		keys = append(keys, claimKeyVisibility)
	}
	if c.allowedCidrs != nil {
		keys = append(keys, claimKeyAllowedCidrs)
	}
	for k := range c.customClaims {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// getClaim returns the value and presence of the named claim.
func (c *Claims) getClaim(name string) (any, bool) {
	switch name {
	case jwt.JwtIDKey:
		if c.tokenID == "" {
			return nil, false
		}
		return c.tokenID, true
	case jwt.SubjectKey:
		if c.subject == "" {
			return nil, false
		}
		return c.subject, true
	case jwt.IssuerKey:
		if c.issuer == "" {
			return nil, false
		}
		return c.issuer, true
	case jwt.AudienceKey:
		if c.audience == nil {
			return nil, false
		}
		return c.audience, true
	case jwt.IssuedAtKey:
		if c.issuedAt.IsZero() {
			return nil, false
		}
		return c.issuedAt, true
	case jwt.ExpirationKey:
		if c.expiresAt.IsZero() {
			return nil, false
		}
		return c.expiresAt, true
	case jwt.NotBeforeKey:
		if c.notBefore.IsZero() {
			return nil, false
		}
		return c.notBefore, true
	case claimKeyTokenType:
		if c.tokenType == "" {
			return nil, false
		}
		return string(c.tokenType), true
	case claimKeyAPIKeyID:
		if c.keyID == "" {
			return nil, false
		}
		return c.keyID, true
	case claimKeyParentID:
		if c.parentID == "" {
			return nil, false
		}
		return c.parentID, true
	case claimKeyActorID:
		if c.actorID == "" {
			return nil, false
		}
		return c.actorID, true
	case claimKeyNetworkID:
		if c.networkID == "" {
			return nil, false
		}
		return c.networkID, true
	case claimKeyScopes, claimKeyScopesAlias:
		if c.scopes == nil {
			return nil, false
		}
		return c.scopes, true
	case claimKeyMetadata:
		if c.metadata == nil {
			return nil, false
		}
		return c.metadata, true
	case claimKeyVisibility:
		if c.visibility == "" {
			return nil, false
		}
		return c.visibility, true
	case claimKeyAllowedCidrs:
		if c.allowedCidrs == nil {
			return nil, false
		}
		return c.allowedCidrs, true
	default:
		if c.customClaims != nil {
			v, ok := c.customClaims[name]
			return v, ok
		}
		return nil, false
	}
}

// Set assigns a value to the named claim with type coercion.
func (c *Claims) Set(name string, value any) error {
	switch name {
	case jwt.JwtIDKey:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.tokenID = v
	case jwt.SubjectKey:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.subject = v
	case jwt.IssuerKey:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.issuer = v
	case jwt.AudienceKey:
		aud, err := coerceStringSlice(name, value, true)
		if err != nil {
			return err
		}
		c.audience = aud
	case jwt.IssuedAtKey:
		t, err := acceptTime(value)
		if err != nil {
			return errors.Wrapf(err, "invalid value for %s", name)
		}
		c.issuedAt = t
	case jwt.ExpirationKey:
		t, err := acceptTime(value)
		if err != nil {
			return errors.Wrapf(err, "invalid value for %s", name)
		}
		c.expiresAt = t
	case jwt.NotBeforeKey:
		t, err := acceptTime(value)
		if err != nil {
			return errors.Wrapf(err, "invalid value for %s", name)
		}
		c.notBefore = t
	case claimKeyTokenType:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.tokenType = TokenType(v)
	case claimKeyAPIKeyID:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.keyID = v
	case claimKeyParentID:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.parentID = v
	case claimKeyActorID:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.actorID = v
	case claimKeyNetworkID:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.networkID = v
	case claimKeyScopes, claimKeyScopesAlias:
		scopes, err := coerceStringSlice(name, value, false)
		if err != nil {
			return err
		}
		c.scopes = scopes
	case claimKeyMetadata:
		v, err := assertType[map[string]any](name, value)
		if err != nil {
			return err
		}
		c.metadata = v
	case claimKeyVisibility:
		v, err := assertType[string](name, value)
		if err != nil {
			return err
		}
		c.visibility = v
	case claimKeyAllowedCidrs:
		cidrs, err := coerceStringSlice(name, value, false)
		if err != nil {
			return err
		}
		c.allowedCidrs = cidrs
	default:
		if c.customClaims == nil {
			c.customClaims = make(map[string]any)
		}
		c.customClaims[name] = value
	}
	return nil
}

// Remove zeros out the named claim.
func (c *Claims) Remove(name string) error {
	switch name {
	case jwt.JwtIDKey:
		c.tokenID = ""
	case jwt.SubjectKey:
		c.subject = ""
	case jwt.IssuerKey:
		c.issuer = ""
	case jwt.AudienceKey:
		c.audience = nil
	case jwt.IssuedAtKey:
		c.issuedAt = time.Time{}
	case jwt.ExpirationKey:
		c.expiresAt = time.Time{}
	case jwt.NotBeforeKey:
		c.notBefore = time.Time{}
	case claimKeyTokenType:
		c.tokenType = ""
	case claimKeyAPIKeyID:
		c.keyID = ""
	case claimKeyParentID:
		c.parentID = ""
	case claimKeyActorID:
		c.actorID = ""
	case claimKeyNetworkID:
		c.networkID = ""
	case claimKeyScopes, claimKeyScopesAlias:
		c.scopes = nil
	case claimKeyMetadata:
		c.metadata = nil
	case claimKeyVisibility:
		c.visibility = ""
	case claimKeyAllowedCidrs:
		c.allowedCidrs = nil
	default:
		if c.customClaims != nil {
			delete(c.customClaims, name)
		}
	}
	return nil
}

// PrivateClaims returns custom (non-standard JWT) claims.
func (c *Claims) PrivateClaims() map[string]any {
	m := make(map[string]any)
	if c.actorID != "" {
		m[claimKeyActorID] = c.actorID
	}
	if c.networkID != "" {
		m[claimKeyNetworkID] = c.networkID
	}
	if c.scopes != nil {
		m[claimKeyScopes] = c.scopes
	}
	if c.metadata != nil {
		m[claimKeyMetadata] = c.metadata
	}
	if c.visibility != "" {
		m[claimKeyVisibility] = c.visibility
	}
	if c.allowedCidrs != nil {
		m[claimKeyAllowedCidrs] = c.allowedCidrs
	}
	copyUnsetClaims(m, c.customClaims)
	return m
}

func copyUnsetClaims(dst, src map[string]any) {
	for k, v := range src {
		if _, exists := dst[k]; exists {
			continue
		}
		dst[k] = v
	}
}

// deepCopyMap copies src into dst, recursively deep-copying nested maps and slices
// so that the clone shares no mutable state with the original.
func deepCopyMap(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = deepCopyValue(v)
	}
}

// deepCopyValue returns a deep copy of a value found in JWT claims.
// Maps and slices are recursively copied; scalar types are returned as-is.
func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		cp := make(map[string]any, len(val))
		deepCopyMap(cp, val)
		return cp
	case []any:
		cp := make([]any, len(val))
		for i, elem := range val {
			cp[i] = deepCopyValue(elem)
		}
		return cp
	default:
		return v
	}
}

// Clone returns a deep copy.
func (c *Claims) Clone() (jwt.Token, error) {
	out := &Claims{
		tokenID:    c.tokenID,
		subject:    c.subject,
		issuer:     c.issuer,
		issuedAt:   c.issuedAt,
		expiresAt:  c.expiresAt,
		notBefore:  c.notBefore,
		tokenType:  c.tokenType,
		keyID:      c.keyID,
		parentID:   c.parentID,
		actorID:    c.actorID,
		networkID:  c.networkID,
		visibility: c.visibility,
		options:    c.options,
	}
	if c.audience != nil {
		out.audience = make([]string, len(c.audience))
		copy(out.audience, c.audience)
	}
	if c.scopes != nil {
		out.scopes = make([]string, len(c.scopes))
		copy(out.scopes, c.scopes)
	}
	if c.metadata != nil {
		out.metadata = make(map[string]any, len(c.metadata))
		deepCopyMap(out.metadata, c.metadata)
	}
	if c.allowedCidrs != nil {
		out.allowedCidrs = make([]string, len(c.allowedCidrs))
		copy(out.allowedCidrs, c.allowedCidrs)
	}
	if c.customClaims != nil {
		out.customClaims = make(map[string]any, len(c.customClaims))
		deepCopyMap(out.customClaims, c.customClaims)
	}
	return out, nil
}

// MarshalJSON serializes claims to JWT-compatible JSON.
// Time claims are encoded as Unix epoch seconds.
// Note: tokenType (tty), keyID (akid), and parentID (pid) are intentionally
// omitted from serialization. For session tokens (the only type serialized to JWT),
// keyID and parentID are redundant with sub, and tokenType is always "session".
// These fields are still parsed during deserialization for backward compatibility.
func (c Claims) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, 14)
	if c.tokenID != "" {
		m[jwt.JwtIDKey] = c.tokenID
	}
	if c.subject != "" {
		m[jwt.SubjectKey] = c.subject
	}
	if c.issuer != "" {
		m[jwt.IssuerKey] = c.issuer
	}
	if len(c.audience) > 0 {
		if c.options.IsEnabled(jwt.FlattenAudience) && len(c.audience) == 1 {
			m[jwt.AudienceKey] = c.audience[0]
		} else {
			m[jwt.AudienceKey] = c.audience
		}
	}
	if !c.issuedAt.IsZero() {
		m[jwt.IssuedAtKey] = c.issuedAt.Unix()
	}
	if !c.expiresAt.IsZero() {
		m[jwt.ExpirationKey] = c.expiresAt.Unix()
	}
	if !c.notBefore.IsZero() {
		m[jwt.NotBeforeKey] = c.notBefore.Unix()
	}
	if c.actorID != "" {
		m[claimKeyActorID] = c.actorID
	}
	if c.networkID != "" {
		m[claimKeyNetworkID] = c.networkID
	}
	if len(c.scopes) > 0 {
		m[claimKeyScopes] = c.scopes
	}
	if len(c.metadata) > 0 {
		m[claimKeyMetadata] = c.metadata
	}
	if c.visibility != "" {
		m[claimKeyVisibility] = c.visibility
	}
	if len(c.allowedCidrs) > 0 {
		m[claimKeyAllowedCidrs] = c.allowedCidrs
	}
	copyUnsetClaims(m, c.customClaims)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	return b[:len(b)-1], nil // trim trailing newline from Encode
}

// UnmarshalJSON deserializes JWT JSON into claims.
func (c *Claims) UnmarshalJSON(data []byte) error {
	// Reset all fields
	*c = Claims{}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.Wrap(err, "unmarshal claims")
	}

	if rawVal, ok := raw[claimKeyScopes]; ok {
		var scopes []string
		if err := json.Unmarshal(rawVal, &scopes); err != nil {
			return errors.Wrapf(err, "unmarshal %s", claimKeyScopes)
		}
		c.scopes = scopes
		delete(raw, claimKeyScopes)
		delete(raw, claimKeyScopesAlias)
	} else if rawVal, ok := raw[claimKeyScopesAlias]; ok {
		var scopes []string
		if err := json.Unmarshal(rawVal, &scopes); err != nil {
			return errors.Wrapf(err, "unmarshal %s", claimKeyScopesAlias)
		}
		c.scopes = scopes
		delete(raw, claimKeyScopesAlias)
	}

	for key, rawVal := range raw {
		switch key {
		case jwt.JwtIDKey:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.tokenID = s
		case jwt.SubjectKey:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.subject = s
		case jwt.IssuerKey:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.issuer = s
		case jwt.AudienceKey:
			// audience can be string or []string
			var aud []string
			if err := json.Unmarshal(rawVal, &aud); err != nil {
				var single string
				if err2 := json.Unmarshal(rawVal, &single); err2 != nil {
					return errors.Wrapf(err, "unmarshal %s", key)
				}
				aud = []string{single}
			}
			c.audience = aud
		case jwt.IssuedAtKey:
			t, err := unmarshalTime(rawVal)
			if err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.issuedAt = t
		case jwt.ExpirationKey:
			t, err := unmarshalTime(rawVal)
			if err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.expiresAt = t
		case jwt.NotBeforeKey:
			t, err := unmarshalTime(rawVal)
			if err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.notBefore = t
		case claimKeyTokenType:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.tokenType = TokenType(s)
		case claimKeyAPIKeyID:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.keyID = s
		case claimKeyParentID:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.parentID = s
		case claimKeyActorID:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.actorID = s
		case claimKeyNetworkID:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.networkID = s
		case claimKeyMetadata:
			var m map[string]any
			if err := json.Unmarshal(rawVal, &m); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.metadata = m
		case claimKeyVisibility:
			var s string
			if err := json.Unmarshal(rawVal, &s); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.visibility = s
		case claimKeyAllowedCidrs:
			var cidrs []string
			if err := json.Unmarshal(rawVal, &cidrs); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			c.allowedCidrs = cidrs
		default:
			// Unknown claims are stored as user-defined top-level claims
			var v any
			if err := json.Unmarshal(rawVal, &v); err != nil {
				return errors.Wrapf(err, "unmarshal %s", key)
			}
			if c.customClaims == nil {
				c.customClaims = make(map[string]any)
			}
			c.customClaims[key] = v
		}
	}

	return nil
}

// acceptTime converts various numeric representations to time.Time.
func acceptTime(v any) (time.Time, error) {
	switch val := v.(type) {
	case time.Time:
		return val, nil
	case float64:
		return time.Unix(int64(val), 0), nil
	case json.Number:
		n, err := val.Int64()
		if err != nil {
			return time.Time{}, errors.Wrap(err, "invalid numeric time")
		}
		return time.Unix(n, 0), nil
	case int64:
		return time.Unix(val, 0), nil
	case int:
		return time.Unix(int64(val), 0), nil
	default:
		return time.Time{}, errors.Wrapf(errUnsupportedTime, "%T", v)
	}
}

// unmarshalTime decodes a JSON numeric time value.
func unmarshalTime(raw json.RawMessage) (time.Time, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return time.Time{}, err
	}
	n, ok := tok.(json.Number)
	if !ok {
		return time.Time{}, errors.Wrapf(errUnsupportedTime, "expected number, got %T", tok)
	}
	epoch, err := n.Int64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(epoch, 0), nil
}

// assertType asserts that value is of type T, returning a typed error on mismatch.
func assertType[T any](name string, value any) (T, error) {
	v, ok := value.(T)
	if !ok {
		var zero T
		return zero, errors.Wrapf(errInvalidClaimType, "expected %T for %s, got %T", zero, name, value)
	}
	return v, nil
}

// coerceStringSlice converts any to []string, accepting []string, []any (of strings),
// and optionally a bare string (wrapped in a single-element slice).
func coerceStringSlice(name string, v any, acceptBareString bool) ([]string, error) {
	switch val := v.(type) {
	case string:
		if !acceptBareString {
			return nil, errors.Wrapf(errInvalidClaimType, "expected []string for %s, got string", name)
		}
		return []string{val}, nil
	case []string:
		return val, nil
	case []any:
		out := make([]string, len(val))
		for i, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, errors.Wrapf(errInvalidClaimType, "%s element %d is not a string: %T", name, i, item)
			}
			out[i] = s
		}
		return out, nil
	default:
		return nil, errors.Wrapf(errInvalidClaimType, "expected []string for %s, got %T", name, v)
	}
}

// reviewed - @aeneasr - 2026-03-25
