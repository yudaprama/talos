// Package persistencetest provides test utilities for persistence package that require the testing package.
package persistencetest

import (
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/gofrs/uuid"

	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
	persistencetypes "github.com/ory-corp/talos/internal/persistence/types"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// fakerSeed is the deterministic seed used by every fixture builder. A fixed
// constant means CI failures replay locally byte-for-byte without per-test
// hash bookkeeping.
const fakerSeed = 1

// fakerMu serializes calls to faker.FakeData. The faker/v4 package mutates
// process-wide state (unique-tag registry, internal reflection caches) on
// every call, so concurrent invocations from parallel test suites race even
// when the random source itself is safe. Driver suites for Postgres, MySQL,
// CockroachDB and SQLite all run with t.Parallel().
//
//nolint:gochecknoglobals // Guards the faker package's own global state; must share lifetime with it.
var fakerMu sync.Mutex

// fakeData wraps faker.FakeData with the shared mutex so parallel driver
// suites cannot race on faker's package-level state.
func fakeData(out any) error {
	fakerMu.Lock()
	defer fakerMu.Unlock()
	return faker.FakeData(out)
}

// init seeds faker's package-level random source and registers the custom
// providers required by the seed wrapper structs. The seed is deterministic
// so generated fixtures are reproducible across runs.
//
// faker mutates package-level state, so any test that calls a newSeed*
// builder must not run in parallel with other faker callers; see the
// concurrency contract on newSeedIssuedKey / newSeedImportedKey.
//
//nolint:gochecknoinits // faker requires global setup before any FakeData call.
func init() {
	faker.SetRandomSource(faker.NewSafeSource(mathrand.NewSource(fakerSeed)))

	mustAddProvider("json_string_array", jsonStringArrayProvider)
	mustAddProvider("json_object", jsonObjectProvider)
	mustAddProvider("cidr_array_v4", cidrArrayV4Provider)
}

func mustAddProvider(tag string, provider func(reflect.Value) (any, error)) {
	if err := faker.AddProvider(tag, provider); err != nil {
		panic(fmt.Sprintf("persistencetest: register faker provider %q: %v", tag, err))
	}
}

// jsonStringArrayProvider returns a JSON-encoded array of three faker words.
// Drives the Scopes column.
func jsonStringArrayProvider(reflect.Value) (any, error) {
	values := []string{faker.Word(), faker.Word(), faker.Word()}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

// jsonObjectProvider returns a JSON-encoded object with two faker keys.
// Drives the Metadata column.
func jsonObjectProvider(reflect.Value) (any, error) {
	encoded, err := json.Marshal(map[string]string{
		faker.Word(): faker.Word(),
		faker.Word(): faker.Word(),
	})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

// cidrArrayV4Provider returns a JSON array of two valid IPv4 CIDR strings.
// Postgres parses allowed_cidrs as `cidr[]` so the values must be syntactically
// valid; randomized network parts keep the diff sensitive to column swaps.
//
// The random network parts come from faker's seeded global source via
// RandomUnixTime so the test fixtures stay deterministic across runs without
// needing crypto-grade randomness for what are non-security values.
func cidrArrayV4Provider(reflect.Value) (any, error) {
	a := faker.RandomUnixTime() % 256
	b := faker.RandomUnixTime() % 256
	c := faker.RandomUnixTime() % 256
	cidrs := []string{
		fmt.Sprintf("10.%d.%d.0/24", a, b),
		fmt.Sprintf("192.168.%d.0/24", c),
	}
	encoded, err := json.Marshal(cidrs)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

// fixtureTimestamp returns a deterministic, UTC, microsecond-truncated timestamp
// distinct from the database server now() so created/updated timestamps stand
// out from server-coerced values during round-trip assertions.
//
// Microsecond truncation matches MySQL DATETIME(6) precision so the fixture
// value survives round-tripping through every supported backend.
func fixtureTimestamp(offset time.Duration) time.Time {
	base := time.Date(2026, 4, 30, 12, 0, 0, 123456000, time.UTC)
	return base.Add(offset).Truncate(time.Microsecond)
}

// seedIssuedKey mirrors db.IssuedApiKey field-for-field with faker tags. It
// exists because faker cannot tag sqlc-generated types directly. The toModel
// method assembles a db.IssuedApiKey from the seeded values plus the manual
// pointer/time fields populated by the builder.
type seedIssuedKey struct {
	KeyID                string          `faker:"word,unique"`
	Name                 string          `faker:"sentence"`
	TokenPrefix          string          `faker:"len=16"`
	ActorID              string          `faker:"word"`
	Scopes               json.RawMessage `faker:"json_string_array"`
	Status               int32           `faker:"oneof: 1, 2, 3"`
	Metadata             json.RawMessage `faker:"json_object"`
	RevocationReason     int32           `faker:"oneof: 1, 2, 3"`
	RevocationReasonText string          `faker:"sentence"`
	AllowedCidrs         json.RawMessage `faker:"cidr_array_v4"`
	RequestID            string          `faker:"word,unique"`
	Visibility           int32           `faker:"oneof: 1, 2"`
}

func (s seedIssuedKey) toModel(nid uuid.UUID) db.IssuedApiKey {
	return db.IssuedApiKey{
		NID:                  nid,
		KeyID:                s.KeyID,
		Name:                 s.Name,
		TokenPrefix:          s.TokenPrefix,
		Version:              1,
		ActorID:              new(s.ActorID),
		Scopes:               s.Scopes,
		Status:               s.Status,
		Metadata:             s.Metadata,
		LastUsedAt:           new(fixtureTimestamp(-time.Hour)),
		ExpiresAt:            new(fixtureTimestamp(90 * 24 * time.Hour)),
		CreatedAt:            fixtureTimestamp(0),
		UpdatedAt:            fixtureTimestamp(time.Minute),
		RateLimitQuota:       new(int64(7411)),
		RateLimitWindow:      new(int64(8517)),
		RevocationReason:     s.RevocationReason,
		RevocationReasonText: new(s.RevocationReasonText),
		AllowedCidrs:         s.AllowedCidrs,
		RequestID:            new(s.RequestID),
		Visibility:           s.Visibility,
	}
}

// seedImportedKey mirrors db.ImportedApiKey field-for-field with faker tags.
type seedImportedKey struct {
	KeyID                string          `faker:"word,unique"`
	Name                 string          `faker:"sentence"`
	ActorID              string          `faker:"word"`
	Scopes               json.RawMessage `faker:"json_string_array"`
	Status               int32           `faker:"oneof: 1, 2, 3"`
	Metadata             json.RawMessage `faker:"json_object"`
	RevocationReason     int32           `faker:"oneof: 1, 2, 3"`
	RevocationReasonText string          `faker:"sentence"`
	AllowedCidrs         json.RawMessage `faker:"cidr_array_v4"`
	RequestID            string          `faker:"word,unique"`
	Visibility           int32           `faker:"oneof: 1, 2"`
}

func (s seedImportedKey) toModel(nid uuid.UUID) db.ImportedApiKey {
	return db.ImportedApiKey{
		NID:                  nid,
		KeyID:                s.KeyID,
		Name:                 s.Name,
		ActorID:              new(s.ActorID),
		Scopes:               s.Scopes,
		Status:               s.Status,
		Metadata:             s.Metadata,
		LastUsedAt:           new(fixtureTimestamp(-2 * time.Hour)),
		ExpiresAt:            new(fixtureTimestamp(180 * 24 * time.Hour)),
		CreatedAt:            fixtureTimestamp(time.Hour),
		UpdatedAt:            fixtureTimestamp(time.Hour + time.Minute),
		RateLimitQuota:       new(int64(2207)),
		RateLimitWindow:      new(int64(3301)),
		RevocationReason:     s.RevocationReason,
		RevocationReasonText: new(s.RevocationReasonText),
		AllowedCidrs:         s.AllowedCidrs,
		RequestID:            new(s.RequestID),
		Visibility:           s.Visibility,
	}
}

// newSeedIssuedKey returns a fully-populated db.IssuedApiKey synthesized via
// faker. faker mutates process-wide state, so concurrent callers serialize
// through fakerMu. The deterministic seed makes a single test run replay
// reproducibly; ordering across parallel suites is intentionally non-strict.
func newSeedIssuedKey(t *testing.T, nid uuid.UUID) db.IssuedApiKey {
	t.Helper()
	var s seedIssuedKey
	if err := fakeData(&s); err != nil {
		t.Fatalf("faker.FakeData(seedIssuedKey): %v", err)
	}
	model := s.toModel(nid)
	assertAllFieldsNonZero(t, model, "NID")
	return model
}

// newSeedImportedKey returns a fully-populated db.ImportedApiKey synthesized
// via faker. Calls are serialized through fakerMu; see newSeedIssuedKey.
func newSeedImportedKey(t *testing.T, nid uuid.UUID) db.ImportedApiKey {
	t.Helper()
	var s seedImportedKey
	if err := fakeData(&s); err != nil {
		t.Fatalf("faker.FakeData(seedImportedKey): %v", err)
	}
	model := s.toModel(nid)
	assertAllFieldsNonZero(t, model, "NID")
	return model
}

// newSeedCreateIssuedAPIKeyParams derives a CreateIssuedAPIKeyParams from a
// freshly-seeded db.IssuedApiKey so the model and the params describe the
// same fixture. The returned model carries the same KeyID/RequestID as the
// params for round-trip diffing.
func newSeedCreateIssuedAPIKeyParams(t *testing.T, nid uuid.UUID) (db.IssuedApiKey, persistencetypes.CreateIssuedAPIKeyParams) {
	t.Helper()
	model := newSeedIssuedKey(t, nid)
	params := persistencetypes.CreateIssuedAPIKeyParams{
		KeyID:           model.KeyID,
		Name:            model.Name,
		TokenPrefix:     model.TokenPrefix,
		ActorID:         *model.ActorID,
		Scopes:          model.Scopes,
		Metadata:        model.Metadata,
		ExpiresAt:       model.ExpiresAt,
		RateLimitQuota:  model.RateLimitQuota,
		RateLimitWindow: model.RateLimitWindow,
		AllowedCIDRs:    model.AllowedCidrs,
		RequestID:       *model.RequestID,
		Visibility:      model.Visibility,
	}
	return model, params
}

// newSeedCreateImportedKeyParams derives a CreateImportedKeyParams from a
// freshly-seeded db.ImportedApiKey.
func newSeedCreateImportedKeyParams(t *testing.T, nid uuid.UUID) (db.ImportedApiKey, persistencetypes.CreateImportedKeyParams) {
	t.Helper()
	model := newSeedImportedKey(t, nid)
	params := persistencetypes.CreateImportedKeyParams{
		KeyID:           model.KeyID,
		ActorID:         *model.ActorID,
		Name:            model.Name,
		Scopes:          model.Scopes,
		Metadata:        model.Metadata,
		Status:          model.Status,
		ExpiresAt:       model.ExpiresAt,
		RateLimitQuota:  model.RateLimitQuota,
		RateLimitWindow: model.RateLimitWindow,
		AllowedCIDRs:    model.AllowedCidrs,
		RequestID:       *model.RequestID,
		Visibility:      model.Visibility,
	}
	return model, params
}

// seedUpdatePayload carries the faker-generated subset of fields used by
// both UpdateIssuedAPIKeyParams and UpdateImportedKeyParams.
type seedUpdatePayload struct {
	Name         string          `faker:"sentence"`
	Scope        string          `faker:"word"`
	Metadata     json.RawMessage `faker:"json_object"`
	AllowedCidrs json.RawMessage `faker:"cidr_array_v4"`
}

func newSeedUpdatePayload(t *testing.T) seedUpdatePayload {
	t.Helper()
	var s seedUpdatePayload
	if err := fakeData(&s); err != nil {
		t.Fatalf("faker.FakeData(seedUpdatePayload): %v", err)
	}
	return s
}

// newSeedUpdateIssuedAPIKeyParams returns an UpdateIssuedAPIKeyParams with
// every mutable field populated.
func newSeedUpdateIssuedAPIKeyParams(t *testing.T, keyID string) persistencetypes.UpdateIssuedAPIKeyParams {
	t.Helper()
	s := newSeedUpdatePayload(t)
	return persistencetypes.UpdateIssuedAPIKeyParams{
		KeyID:           keyID,
		Name:            s.Name,
		Scopes:          []string{s.Scope},
		Metadata:        s.Metadata,
		RateLimitQuota:  new(int64(9931)),
		RateLimitWindow: new(int64(7919)),
		AllowedCIDRs:    s.AllowedCidrs,
	}
}

// newSeedUpdateImportedKeyParams returns an UpdateImportedKeyParams with
// every mutable field populated.
func newSeedUpdateImportedKeyParams(t *testing.T, keyID string) persistencetypes.UpdateImportedKeyParams {
	t.Helper()
	s := newSeedUpdatePayload(t)
	return persistencetypes.UpdateImportedKeyParams{
		KeyID:           keyID,
		Name:            s.Name,
		Scopes:          []string{s.Scope},
		Metadata:        s.Metadata,
		RateLimitQuota:  new(int64(7321)),
		RateLimitWindow: new(int64(6217)),
		AllowedCIDRs:    s.AllowedCidrs,
	}
}

// seedRevokePayload carries the faker-generated description used in revoke
// operations. Reason is fixed to KEY_COMPROMISE — the round-trip test asserts
// the persisted reason matches whatever the params carry.
type seedRevokePayload struct {
	Description string `faker:"sentence"`
}

func newSeedRevokePayload(t *testing.T) seedRevokePayload {
	t.Helper()
	var s seedRevokePayload
	if err := fakeData(&s); err != nil {
		t.Fatalf("faker.FakeData(seedRevokePayload): %v", err)
	}
	return s
}

// newSeedRevokeIssuedAPIKeyParams returns a RevokeIssuedAPIKeyParams with
// every field populated.
func newSeedRevokeIssuedAPIKeyParams(t *testing.T, keyID string) persistencetypes.RevokeIssuedAPIKeyParams {
	t.Helper()
	s := newSeedRevokePayload(t)
	return persistencetypes.RevokeIssuedAPIKeyParams{
		KeyID:       keyID,
		Reason:      int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
		Description: s.Description,
		ExpiresAt:   new(fixtureTimestamp(time.Hour)),
	}
}

// newSeedRevokeImportedKeyParams returns a RevokeImportedKeyParams with every
// field populated.
func newSeedRevokeImportedKeyParams(t *testing.T, keyID string) persistencetypes.RevokeImportedKeyParams {
	t.Helper()
	s := newSeedRevokePayload(t)
	return persistencetypes.RevokeImportedKeyParams{
		KeyID:       keyID,
		Reason:      int32(talosv2alpha1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE),
		Description: s.Description,
		ExpiresAt:   new(fixtureTimestamp(2 * time.Hour)),
	}
}

// zeroProbe is the optional interface used to detect "logically zero" values
// even when reflect.Value.IsZero would say non-zero (for example, a non-nil
// pointer pointing to a zero time.Time).
type zeroProbe interface {
	IsZero() bool
}

// assertAllFieldsNonZero walks the exported fields of v via reflection and
// fails the test for any field that is logically zero. The check probes for
// IsZero() bool first to avoid false negatives on time.Time wrapped behind a
// pointer, then dereferences pointers and recurses, finally falling back to
// reflect.Value.IsZero.
//
// Field names listed in exempt are skipped — useful for fields whose value is
// driver-controlled (for example, NID on OSS SQLite is always uuid.Nil).
//
// The error message includes the struct and field name so a missing fixture
// population surfaces as "<TypeName>.<FieldName> is zero — update Build...".
func assertAllFieldsNonZero(t *testing.T, v any, exempt ...string) {
	t.Helper()
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		t.Fatalf("assertAllFieldsNonZero: expected struct, got %s", rv.Kind())
	}
	rt := rv.Type()
	for i := range rt.NumField() {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}
		if slices.Contains(exempt, field.Name) {
			continue
		}
		if isLogicallyZero(rv.Field(i)) {
			t.Errorf("%s.%s is zero — update newSeed* fixture builder", rt.Name(), field.Name)
		}
	}
}

// isLogicallyZero reports whether the reflect.Value is zero in the sense of
// "the fixture builder forgot to set it". It implements the IsZero probe
// described in the plan.
func isLogicallyZero(rv reflect.Value) bool {
	if !rv.IsValid() {
		return true
	}
	// Pointer: nil is zero; otherwise probe the pointee.
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return true
		}
		// Recurse on pointee so a *time.Time pointing to a zero time is caught.
		return isLogicallyZero(rv.Elem())
	}
	// Slice / map: nil or empty is zero.
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Map {
		// For json.RawMessage, also reject "null" / whitespace-only as logically empty.
		if rv.Type().Name() == "RawMessage" || rv.Type().String() == "json.RawMessage" {
			b, _ := rv.Interface().(json.RawMessage)
			return isJSONZero(b)
		}
		return rv.Len() == 0
	}
	// IsZero probe (e.g., time.Time{}.IsZero()).
	if rv.CanInterface() {
		if z, ok := rv.Interface().(zeroProbe); ok {
			return z.IsZero()
		}
	}
	return rv.IsZero()
}

// isJSONZero reports whether a json.RawMessage is logically empty (nil, empty,
// whitespace, or the literal "null").
func isJSONZero(b json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" {
		return true
	}
	if trimmed == "null" {
		return true
	}
	return false
}
