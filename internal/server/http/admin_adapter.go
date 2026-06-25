package http

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ory/talos/internal/service"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// adminAdapter adapts service.Admin and service.Public to the
// ApiKeysServer interface, routing HTTP requests directly to the
// service layer. Verification helpers (AdminVerifyApiKey, AdminBatchVerifyApiKeys)
// delegate to the Public type because they share the same verifier
// implementation, but they are exposed only on the admin surface.
// RevokeApiKey is the proof-of-possession self-revocation variant, also
// delegated to Public, and exposed in all-in-one mode.
type adminAdapter struct {
	talosv2alpha1.UnimplementedApiKeysServer

	svc    *service.Admin
	public *service.Public
}

func (a *adminAdapter) AdminIssueApiKey(ctx context.Context, req *talosv2alpha1.IssueApiKeyRequest) (*talosv2alpha1.IssueApiKeyResponse, error) {
	return a.svc.IssueApiKey(ctx, req)
}

func (a *adminAdapter) AdminGetIssuedApiKey(ctx context.Context, req *talosv2alpha1.GetIssuedApiKeyRequest) (*talosv2alpha1.IssuedApiKey, error) {
	return a.svc.GetIssuedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminRotateIssuedApiKey(ctx context.Context, req *talosv2alpha1.RotateIssuedApiKeyRequest) (*talosv2alpha1.RotateIssuedApiKeyResponse, error) {
	return a.svc.RotateIssuedApiKey(ctx, req)
}

func (a *adminAdapter) AdminRevokeIssuedApiKey(ctx context.Context, req *talosv2alpha1.RevokeIssuedApiKeyRequest) (*emptypb.Empty, error) {
	return a.svc.RevokeIssuedApiKey(ctx, req)
}

func (a *adminAdapter) AdminRevokeImportedApiKey(ctx context.Context, req *talosv2alpha1.RevokeImportedApiKeyRequest) (*emptypb.Empty, error) {
	return a.svc.RevokeImportedApiKey(ctx, req)
}

func (a *adminAdapter) AdminListIssuedApiKeys(ctx context.Context, req *talosv2alpha1.ListIssuedApiKeysRequest) (*talosv2alpha1.ListIssuedApiKeysResponse, error) {
	return a.svc.ListIssuedAPIKeys(ctx, req)
}

func (a *adminAdapter) AdminDeriveToken(ctx context.Context, req *talosv2alpha1.DeriveTokenRequest) (*talosv2alpha1.DeriveTokenResponse, error) {
	return a.svc.DeriveToken(ctx, req)
}

func (a *adminAdapter) GetJwks(ctx context.Context, req *talosv2alpha1.GetJWKSRequest) (*talosv2alpha1.GetJWKSResponse, error) {
	return a.public.GetJwks(ctx, req)
}

func (a *adminAdapter) AdminImportApiKey(ctx context.Context, req *talosv2alpha1.ImportApiKeyRequest) (*talosv2alpha1.ImportedApiKey, error) {
	return a.svc.ImportAPIKey(ctx, req)
}

func (a *adminAdapter) AdminBatchCreateImportedApiKeys(ctx context.Context, req *talosv2alpha1.BatchCreateImportedApiKeysRequest) (*talosv2alpha1.BatchCreateImportedApiKeysResponse, error) {
	return a.svc.BatchImportAPIKeys(ctx, req)
}

func (a *adminAdapter) AdminListImportedApiKeys(ctx context.Context, req *talosv2alpha1.ListImportedApiKeysRequest) (*talosv2alpha1.ListImportedApiKeysResponse, error) {
	return a.svc.ListImportedAPIKeys(ctx, req)
}

func (a *adminAdapter) AdminGetImportedApiKey(ctx context.Context, req *talosv2alpha1.GetImportedApiKeyRequest) (*talosv2alpha1.ImportedApiKey, error) {
	return a.svc.GetImportedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminDeleteImportedApiKey(ctx context.Context, req *talosv2alpha1.DeleteImportedApiKeyRequest) (*emptypb.Empty, error) {
	return a.svc.DeleteImportedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminUpdateIssuedApiKey(ctx context.Context, req *talosv2alpha1.UpdateIssuedApiKeyRequest) (*talosv2alpha1.IssuedApiKey, error) {
	return a.svc.UpdateIssuedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminUpdateImportedApiKey(ctx context.Context, req *talosv2alpha1.UpdateImportedApiKeyRequest) (*talosv2alpha1.ImportedApiKey, error) {
	return a.svc.UpdateImportedAPIKey(ctx, req)
}

// AdminVerifyApiKey verifies an admin-supplied credential by delegating to the
// shared verifier helper on Public. The endpoint itself is admin-only.
func (a *adminAdapter) AdminVerifyApiKey(ctx context.Context, req *talosv2alpha1.VerifyApiKeyRequest) (*talosv2alpha1.VerifyApiKeyResponse, error) {
	return a.public.VerifyAPIKey(ctx, req)
}

// AdminBatchVerifyApiKeys verifies admin-supplied credentials in batch by
// delegating to the shared verifier helper on Public. The endpoint itself
// is admin-only.
func (a *adminAdapter) AdminBatchVerifyApiKeys(ctx context.Context, req *talosv2alpha1.BatchVerifyApiKeysRequest) (*talosv2alpha1.BatchVerifyApiKeysResponse, error) {
	return a.public.BatchVerifyAPIKeys(ctx, req)
}

// AdminIngestUsage records usage and debits the actor's balance (metering fork).
func (a *adminAdapter) AdminIngestUsage(ctx context.Context, req *talosv2alpha1.IngestUsageRequest) (*talosv2alpha1.IngestUsageResponse, error) {
	return a.public.IngestUsage(ctx, req)
}

// AdminSetActorQuota sets an actor's quota and resets remaining (metering fork).
func (a *adminAdapter) AdminSetActorQuota(ctx context.Context, req *talosv2alpha1.SetActorQuotaRequest) (*talosv2alpha1.ActorBalance, error) {
	return a.public.SetActorQuota(ctx, req)
}

// AdminTopUpBalance adds credits to an actor's remaining balance (metering fork).
func (a *adminAdapter) AdminTopUpBalance(ctx context.Context, req *talosv2alpha1.TopUpBalanceRequest) (*talosv2alpha1.ActorBalance, error) {
	return a.public.TopUpBalance(ctx, req)
}

// AdminGetActorBalance reads an actor's current balance (metering fork).
func (a *adminAdapter) AdminGetActorBalance(ctx context.Context, req *talosv2alpha1.GetActorBalanceRequest) (*talosv2alpha1.ActorBalance, error) {
	return a.public.GetActorBalance(ctx, req)
}

// RevokeApiKey is the proof-of-possession self-revocation variant. It delegates
// to Public so the credential holder can revoke their own key without admin
// privileges.
func (a *adminAdapter) RevokeApiKey(ctx context.Context, req *talosv2alpha1.SelfRevokeApiKeyRequest) (*talosv2alpha1.SelfRevokeApiKeyResponse, error) {
	return a.public.RevokeApiKey(ctx, req)
}

// adminOnlyAdapter exposes all Admin* methods but leaves RevokeApiKey (the
// proof-of-possession variant) wired to the embedded UnimplementedApiKeysServer,
// which returns codes.Unimplemented → HTTP 404. Used when the server runs in
// ModeAdmin.
type adminOnlyAdapter struct {
	talosv2alpha1.UnimplementedApiKeysServer

	svc    *service.Admin
	public *service.Public
}

func (a *adminOnlyAdapter) AdminIssueApiKey(ctx context.Context, req *talosv2alpha1.IssueApiKeyRequest) (*talosv2alpha1.IssueApiKeyResponse, error) {
	return a.svc.IssueApiKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminGetIssuedApiKey(ctx context.Context, req *talosv2alpha1.GetIssuedApiKeyRequest) (*talosv2alpha1.IssuedApiKey, error) {
	return a.svc.GetIssuedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminRotateIssuedApiKey(ctx context.Context, req *talosv2alpha1.RotateIssuedApiKeyRequest) (*talosv2alpha1.RotateIssuedApiKeyResponse, error) {
	return a.svc.RotateIssuedApiKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminRevokeIssuedApiKey(ctx context.Context, req *talosv2alpha1.RevokeIssuedApiKeyRequest) (*emptypb.Empty, error) {
	return a.svc.RevokeIssuedApiKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminRevokeImportedApiKey(ctx context.Context, req *talosv2alpha1.RevokeImportedApiKeyRequest) (*emptypb.Empty, error) {
	return a.svc.RevokeImportedApiKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminListIssuedApiKeys(ctx context.Context, req *talosv2alpha1.ListIssuedApiKeysRequest) (*talosv2alpha1.ListIssuedApiKeysResponse, error) {
	return a.svc.ListIssuedAPIKeys(ctx, req)
}

func (a *adminOnlyAdapter) AdminDeriveToken(ctx context.Context, req *talosv2alpha1.DeriveTokenRequest) (*talosv2alpha1.DeriveTokenResponse, error) {
	return a.svc.DeriveToken(ctx, req)
}

func (a *adminOnlyAdapter) GetJwks(ctx context.Context, req *talosv2alpha1.GetJWKSRequest) (*talosv2alpha1.GetJWKSResponse, error) {
	return a.public.GetJwks(ctx, req)
}

func (a *adminOnlyAdapter) AdminImportApiKey(ctx context.Context, req *talosv2alpha1.ImportApiKeyRequest) (*talosv2alpha1.ImportedApiKey, error) {
	return a.svc.ImportAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminBatchCreateImportedApiKeys(ctx context.Context, req *talosv2alpha1.BatchCreateImportedApiKeysRequest) (*talosv2alpha1.BatchCreateImportedApiKeysResponse, error) {
	return a.svc.BatchImportAPIKeys(ctx, req)
}

func (a *adminOnlyAdapter) AdminListImportedApiKeys(ctx context.Context, req *talosv2alpha1.ListImportedApiKeysRequest) (*talosv2alpha1.ListImportedApiKeysResponse, error) {
	return a.svc.ListImportedAPIKeys(ctx, req)
}

func (a *adminOnlyAdapter) AdminGetImportedApiKey(ctx context.Context, req *talosv2alpha1.GetImportedApiKeyRequest) (*talosv2alpha1.ImportedApiKey, error) {
	return a.svc.GetImportedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminDeleteImportedApiKey(ctx context.Context, req *talosv2alpha1.DeleteImportedApiKeyRequest) (*emptypb.Empty, error) {
	return a.svc.DeleteImportedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminUpdateIssuedApiKey(ctx context.Context, req *talosv2alpha1.UpdateIssuedApiKeyRequest) (*talosv2alpha1.IssuedApiKey, error) {
	return a.svc.UpdateIssuedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminUpdateImportedApiKey(ctx context.Context, req *talosv2alpha1.UpdateImportedApiKeyRequest) (*talosv2alpha1.ImportedApiKey, error) {
	return a.svc.UpdateImportedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminVerifyApiKey(ctx context.Context, req *talosv2alpha1.VerifyApiKeyRequest) (*talosv2alpha1.VerifyApiKeyResponse, error) {
	return a.public.VerifyAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminBatchVerifyApiKeys(ctx context.Context, req *talosv2alpha1.BatchVerifyApiKeysRequest) (*talosv2alpha1.BatchVerifyApiKeysResponse, error) {
	return a.public.BatchVerifyAPIKeys(ctx, req)
}

// publicOnlyAdapter exposes RevokeApiKey (the proof-of-possession variant) and
// GetJwks (a public verification key endpoint per RFC 7517). All Admin*
// methods fall through to the embedded UnimplementedApiKeysServer, which
// returns codes.Unimplemented → HTTP 404. Used when the server runs in
// ModePublic.
type publicOnlyAdapter struct {
	talosv2alpha1.UnimplementedApiKeysServer

	public *service.Public
}

func (a *publicOnlyAdapter) RevokeApiKey(ctx context.Context, req *talosv2alpha1.SelfRevokeApiKeyRequest) (*talosv2alpha1.SelfRevokeApiKeyResponse, error) {
	return a.public.RevokeApiKey(ctx, req)
}

func (a *publicOnlyAdapter) GetJwks(ctx context.Context, req *talosv2alpha1.GetJWKSRequest) (*talosv2alpha1.GetJWKSResponse, error) {
	return a.public.GetJwks(ctx, req)
}

// NewAllInOneAdapter creates an adapter that wires every method: all Admin*
// operations and the proof-of-possession RevokeApiKey. Used in ModeAllInOne.
func NewAllInOneAdapter(svc *service.Admin, public *service.Public) talosv2alpha1.ApiKeysServer {
	return &adminAdapter{svc: svc, public: public}
}

// NewAdminOnlyAdapter creates an adapter that wires all Admin* methods but
// leaves RevokeApiKey returning Unimplemented (→ HTTP 404). Used in ModeAdmin.
// public is still required because AdminVerifyApiKey and
// AdminBatchVerifyApiKeys delegate to it.
func NewAdminOnlyAdapter(svc *service.Admin, public *service.Public) talosv2alpha1.ApiKeysServer {
	return &adminOnlyAdapter{svc: svc, public: public}
}

// NewPublicOnlyAdapter creates an adapter that wires RevokeApiKey and GetJwks.
// All Admin* methods return Unimplemented (→ HTTP 404). Used in ModePublic.
func NewPublicOnlyAdapter(public *service.Public) talosv2alpha1.ApiKeysServer {
	return &publicOnlyAdapter{public: public}
}

// reviewed - @aeneasr - 2026-03-26
