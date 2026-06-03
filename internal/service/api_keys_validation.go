package service

import (
	"encoding/json"
	"time"

	"github.com/cockroachdb/errors"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ory/talos/internal/clientip"
	"github.com/ory/talos/internal/errdef"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
	"github.com/ory/talos/internal/persistence/sqlutil"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// Type Conversion Helpers

func maybeProtoTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func metadataToStructpb(metadata json.RawMessage) *structpb.Struct {
	if len(metadata) <= 2 || string(metadata) == "{}" {
		return nil
	}

	value := &structpb.Struct{}
	if err := value.UnmarshalJSON(metadata); err != nil {
		return nil
	}

	return value
}

func buildRateLimitPolicy(quota, window *int64) *talosv2alpha1.RateLimitPolicy {
	if quota == nil || window == nil {
		return nil
	}

	return &talosv2alpha1.RateLimitPolicy{
		Quota:  *quota,
		Window: durationpb.New(time.Duration(*window) * time.Second),
		Unit:   "requests",
	}
}

// dbAPIKeyFields holds the common proto fields shared by IssuedApiKey and ImportedApiKey.
// Both message types are structurally identical; this helper avoids duplicating the mapping logic.
type dbAPIKeyFields struct {
	keyID                 string
	name                  string
	actorID               string
	scopes                []string
	metadata              *structpb.Struct
	status                talosv2alpha1.KeyStatus
	lastUsedTime          *timestamppb.Timestamp
	createTime            *timestamppb.Timestamp
	updateTime            *timestamppb.Timestamp
	expireTime            *timestamppb.Timestamp
	visibility            talosv2alpha1.KeyVisibility
	revocationReason      *talosv2alpha1.RevocationReason
	revocationDescription *string
	rateLimitPolicy       *talosv2alpha1.RateLimitPolicy
	ipRestriction         *talosv2alpha1.IPRestriction
}

// dbAPIKeyCommonFields extracts the fields that IssuedApiKey and ImportedApiKey share.
// DB column names use _at suffix; proto uses _time suffix.
func dbAPIKeyCommonFields(key db.IssuedApiKey) (dbAPIKeyFields, error) {
	scopes, err := sqlutil.UnmarshalScopes(key.Scopes)
	if err != nil {
		return dbAPIKeyFields{}, err
	}

	f := dbAPIKeyFields{
		keyID:        key.KeyID,
		name:         key.Name,
		actorID:      sqlutil.Deref(key.ActorID),
		scopes:       scopes,
		metadata:     metadataToStructpb(key.Metadata),
		status:       talosv2alpha1.KeyStatus(key.Status),
		lastUsedTime: maybeProtoTimestamp(key.LastUsedAt),
		createTime:   timestamppb.New(key.CreatedAt),
		updateTime:   timestamppb.New(key.UpdatedAt),
		expireTime:   maybeProtoTimestamp(key.ExpiresAt),
		visibility:   talosv2alpha1.KeyVisibility(key.Visibility),
	}
	if key.RevocationReason != 0 {
		r := talosv2alpha1.RevocationReason(key.RevocationReason)
		f.revocationReason = &r
	}
	f.revocationDescription = key.RevocationReasonText
	f.rateLimitPolicy = buildRateLimitPolicy(key.RateLimitQuota, key.RateLimitWindow)
	if cidrs := clientip.UnmarshalCIDRs(key.AllowedCidrs); len(cidrs) > 0 {
		f.ipRestriction = &talosv2alpha1.IPRestriction{
			AllowedCidrs: sqlutil.NonNilSlice(cidrs),
		}
	}
	return f, nil
}

// dbIssuedKeyToProto converts a db.IssuedApiKey to *talosv2alpha1.IssuedApiKey
func dbIssuedKeyToProto(key db.IssuedApiKey) (*talosv2alpha1.IssuedApiKey, error) {
	f, err := dbAPIKeyCommonFields(key)
	if err != nil {
		return nil, err
	}
	return &talosv2alpha1.IssuedApiKey{
		KeyId:                 f.keyID,
		Name:                  f.name,
		ActorId:               f.actorID,
		Scopes:                f.scopes,
		Metadata:              f.metadata,
		Status:                f.status,
		LastUsedTime:          f.lastUsedTime,
		CreateTime:            f.createTime,
		UpdateTime:            f.updateTime,
		ExpireTime:            f.expireTime,
		Visibility:            f.visibility,
		RevocationReason:      f.revocationReason,
		RevocationDescription: f.revocationDescription,
		RateLimitPolicy:       f.rateLimitPolicy,
		IpRestriction:         f.ipRestriction,
	}, nil
}

// dbImportedKeyToProto converts a db.IssuedApiKey (from imported_api_keys table) to *talosv2alpha1.ImportedApiKey
func dbImportedKeyToProto(key db.IssuedApiKey) (*talosv2alpha1.ImportedApiKey, error) {
	f, err := dbAPIKeyCommonFields(key)
	if err != nil {
		return nil, err
	}
	return &talosv2alpha1.ImportedApiKey{
		KeyId:                 f.keyID,
		Name:                  f.name,
		ActorId:               f.actorID,
		Scopes:                f.scopes,
		Metadata:              f.metadata,
		Status:                f.status,
		LastUsedTime:          f.lastUsedTime,
		CreateTime:            f.createTime,
		UpdateTime:            f.updateTime,
		ExpireTime:            f.expireTime,
		Visibility:            f.visibility,
		RevocationReason:      f.revocationReason,
		RevocationDescription: f.revocationDescription,
		RateLimitPolicy:       f.rateLimitPolicy,
		IpRestriction:         f.ipRestriction,
	}, nil
}

func wrapDecodePersistedScopesError(err error) error {
	return errdef.InternalError("decode persisted scopes").WithWrap(errors.WithStack(err))
}

// reviewed - @aeneasr - 2026-03-26
