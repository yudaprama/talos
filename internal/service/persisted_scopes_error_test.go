package service_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/cockroachdb/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"
	"github.com/ory/x/configx"
	"github.com/ory/x/httpx"

	"github.com/ory/talos/internal/cache"
	"github.com/ory/talos/internal/crypto"
	"github.com/ory/talos/internal/events"
	"github.com/ory/talos/internal/lastused"
	"github.com/ory/talos/internal/metrics"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/postgres"
	"github.com/ory/talos/internal/ratelimit"
	"github.com/ory/talos/internal/service"
	"github.com/ory/talos/internal/testutil"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

type corruptScopesPersister struct {
	*postgres.Driver

	corruptIssuedKeys map[string]struct{}
}

func newCorruptScopesPersister(driver *postgres.Driver) *corruptScopesPersister {
	return &corruptScopesPersister{
		Driver:            driver,
		corruptIssuedKeys: make(map[string]struct{}),
	}
}

func (p *corruptScopesPersister) markIssuedKeyCorrupt(keyID string) {
	p.corruptIssuedKeys[keyID] = struct{}{}
}

func (p *corruptScopesPersister) maybeCorruptIssuedKey(row db.IssuedApiKey) db.IssuedApiKey {
	if _, ok := p.corruptIssuedKeys[row.KeyID]; ok {
		row.Scopes = json.RawMessage(`{"oops"`)
	}
	return row
}

func (p *corruptScopesPersister) GetIssuedAPIKey(ctx context.Context, keyID string) (db.IssuedApiKey, error) {
	row, err := p.Driver.GetIssuedAPIKey(ctx, keyID)
	if err != nil {
		return db.IssuedApiKey{}, err
	}
	return p.maybeCorruptIssuedKey(row), nil
}

func (p *corruptScopesPersister) GetIssuedAPIKeysBatch(ctx context.Context, keyIDs []string) ([]db.IssuedApiKey, error) {
	rows, err := p.Driver.GetIssuedAPIKeysBatch(ctx, keyIDs)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i] = p.maybeCorruptIssuedKey(rows[i])
	}
	return rows, nil
}

func (p *corruptScopesPersister) ListIssuedAPIKeysByNetwork(ctx context.Context, actorID string, statusFilter int32, cursorKeyID string, limit int64) ([]db.IssuedApiKey, error) {
	rows, err := p.Driver.ListIssuedAPIKeysByNetwork(ctx, actorID, statusFilter, cursorKeyID, limit)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i] = p.maybeCorruptIssuedKey(rows[i])
	}
	return rows, nil
}

func setupPersistedScopesFailureEnv(t *testing.T) (*corruptScopesPersister, *service.Admin, *service.Public, context.Context) {
	t.Helper()
	ctx := testCtx(t)

	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = driver.Close()
	})
	persister := newCorruptScopesPersister(driver)

	provider := testutil.NewTestProviderWithSigningKeys(t, configx.WithValues(baseTestConfig()))
	keyService, err := crypto.NewKeyService(ctx, provider, httpx.NewResilientClient(), crypto.NoopKeyServiceMetrics())
	require.NoError(t, err)

	pv, err := protovalidate.New()
	require.NoError(t, err)

	tracker := lastused.New(ctx, driver, lastused.Config{
		QueueSize: 100, FlushSize: 100, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tracker.Close)

	apiKeyCache := cache.NewNoopCache[db.IssuedApiKey]()
	m := metrics.New(prometheus.NewRegistry())
	cp := service.NewAdminFromProvider(persister, provider, events.NewNoopEmitter(), keyService, apiKeyCache, pv, m, tracker)
	server := service.NewPublic(cp.Verifier(), pv, &ratelimit.NoopLimiter{}, nil)

	return persister, cp, server, ctx
}

func TestVerifyAPIKey_CorruptPersistedScopesReturnsInternalResponse(t *testing.T) {
	t.Parallel()

	driver, cp, server, ctx := setupPersistedScopesFailureEnv(t)

	issueResp, err := cp.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Corrupt Verify",
		ActorId: "actor-verify",
		Scopes:  []string{"read"},
	})
	require.NoError(t, err)

	driver.markIssuedKeyCorrupt(issueResp.GetIssuedApiKey().GetKeyId())

	verifyResp, err := server.VerifyAPIKey(ctx, &talosv2alpha1.VerifyApiKeyRequest{
		Credential: issueResp.GetSecret(),
	})
	require.NoError(t, err)
	require.NotNil(t, verifyResp)
	assert.False(t, verifyResp.GetIsValid())
	assert.Equal(t, talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INTERNAL, verifyResp.GetErrorCode())
	assert.Equal(t, "decode persisted scopes", verifyResp.GetErrorMessage())
}

func TestBatchVerifyAPIKeys_CorruptPersistedScopesOnlyFailsAffectedItem(t *testing.T) {
	t.Parallel()

	driver, cp, server, ctx := setupPersistedScopesFailureEnv(t)

	validResp, err := cp.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Valid Batch Key",
		ActorId: "actor-valid",
		Scopes:  []string{"read"},
	})
	require.NoError(t, err)

	corruptResp, err := cp.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Corrupt Batch Key",
		ActorId: "actor-corrupt",
		Scopes:  []string{"write"},
	})
	require.NoError(t, err)

	driver.markIssuedKeyCorrupt(corruptResp.GetIssuedApiKey().GetKeyId())

	batchResp, err := server.BatchVerifyAPIKeys(ctx, &talosv2alpha1.BatchVerifyApiKeysRequest{
		Requests: []*talosv2alpha1.VerifyApiKeyRequest{
			{Credential: validResp.GetSecret()},
			{Credential: corruptResp.GetSecret()},
		},
	})
	require.NoError(t, err)
	require.Len(t, batchResp.GetResults(), 2)

	assert.True(t, batchResp.GetResults()[0].GetIsValid())
	assert.Equal(t, validResp.GetIssuedApiKey().GetKeyId(), batchResp.GetResults()[0].GetKeyId())

	assert.False(t, batchResp.GetResults()[1].GetIsValid())
	assert.Equal(t, talosv2alpha1.VerificationErrorCode_VERIFICATION_ERROR_INTERNAL, batchResp.GetResults()[1].GetErrorCode())
	assert.Equal(t, "decode persisted scopes", batchResp.GetResults()[1].GetErrorMessage())
}

func TestListIssuedAPIKeys_CorruptPersistedScopesFailsWholeRequest(t *testing.T) {
	t.Parallel()

	driver, cp, _, ctx := setupPersistedScopesFailureEnv(t)

	firstResp, err := cp.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "First Key",
		ActorId: "actor-first",
		Scopes:  []string{"read"},
	})
	require.NoError(t, err)

	secondResp, err := cp.IssueApiKey(ctx, &talosv2alpha1.IssueApiKeyRequest{
		Name:    "Second Key",
		ActorId: "actor-second",
		Scopes:  []string{"write"},
	})
	require.NoError(t, err)

	driver.markIssuedKeyCorrupt(secondResp.GetIssuedApiKey().GetKeyId())

	resp, err := cp.ListIssuedAPIKeys(ctx, &talosv2alpha1.ListIssuedApiKeysRequest{
		PageSize: 10,
	})
	require.Nil(t, resp)
	require.Error(t, err)
	var herodotErr *herodot.DefaultError
	require.True(t, errors.As(err, &herodotErr))
	assert.Contains(t, herodotErr.ReasonField, "decode persisted scopes")

	// Sanity-check the valid row still exists; the failure is caused by aborting
	// the list conversion on the corrupt sibling row, not by missing data.
	getResp, getErr := cp.GetIssuedAPIKey(ctx, &talosv2alpha1.GetIssuedApiKeyRequest{
		KeyId: firstResp.GetIssuedApiKey().GetKeyId(),
	})
	require.NoError(t, getErr)
	require.NotNil(t, getResp)
}
