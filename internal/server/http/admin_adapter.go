package http

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/ory/talos/internal/service"
	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

// adminAdapter adapts service.Admin and service.Public to the
// APIKeysServer interface, routing HTTP requests directly to the
// service layer. Verification helpers (AdminVerifyAPIKey, AdminBatchVerifyAPIKeys)
// delegate to the Public type because they share the same verifier
// implementation, but they are exposed only on the admin surface.
// RevokeAPIKey is the proof-of-possession self-revocation variant, also
// delegated to Public, and exposed in all-in-one mode.
type adminAdapter struct {
	talosv2alpha1.UnimplementedAPIKeysServer

	svc    *service.Admin
	public *service.Public
}

func (a *adminAdapter) AdminIssueAPIKey(ctx context.Context, req *talosv2alpha1.IssueAPIKeyRequest) (*talosv2alpha1.IssueAPIKeyResponse, error) {
	return a.svc.IssueAPIKey(ctx, req)
}

func (a *adminAdapter) AdminGetIssuedAPIKey(ctx context.Context, req *talosv2alpha1.GetIssuedAPIKeyRequest) (*talosv2alpha1.IssuedAPIKey, error) {
	return a.svc.GetIssuedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminRotateIssuedAPIKey(ctx context.Context, req *talosv2alpha1.RotateIssuedAPIKeyRequest) (*talosv2alpha1.RotateIssuedAPIKeyResponse, error) {
	return a.svc.RotateIssuedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminRevokeIssuedAPIKey(ctx context.Context, req *talosv2alpha1.RevokeIssuedAPIKeyRequest) (*emptypb.Empty, error) {
	return a.svc.RevokeIssuedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminRevokeImportedAPIKey(ctx context.Context, req *talosv2alpha1.RevokeImportedAPIKeyRequest) (*emptypb.Empty, error) {
	return a.svc.RevokeImportedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminListIssuedAPIKeys(ctx context.Context, req *talosv2alpha1.ListIssuedAPIKeysRequest) (*talosv2alpha1.ListIssuedAPIKeysResponse, error) {
	return a.svc.ListIssuedAPIKeys(ctx, req)
}

func (a *adminAdapter) AdminDeriveToken(ctx context.Context, req *talosv2alpha1.DeriveTokenRequest) (*talosv2alpha1.DeriveTokenResponse, error) {
	return a.svc.DeriveToken(ctx, req)
}

func (a *adminAdapter) GetJWKS(ctx context.Context, req *talosv2alpha1.GetJWKSRequest) (*talosv2alpha1.GetJWKSResponse, error) {
	return a.public.GetJWKS(ctx, req)
}

func (a *adminAdapter) AdminImportAPIKey(ctx context.Context, req *talosv2alpha1.ImportAPIKeyRequest) (*talosv2alpha1.ImportedAPIKey, error) {
	return a.svc.ImportAPIKey(ctx, req)
}

func (a *adminAdapter) AdminBatchImportAPIKeys(ctx context.Context, req *talosv2alpha1.BatchImportAPIKeysRequest) (*talosv2alpha1.BatchImportAPIKeysResponse, error) {
	return a.svc.BatchImportAPIKeys(ctx, req)
}

func (a *adminAdapter) AdminListImportedAPIKeys(ctx context.Context, req *talosv2alpha1.ListImportedAPIKeysRequest) (*talosv2alpha1.ListImportedAPIKeysResponse, error) {
	return a.svc.ListImportedAPIKeys(ctx, req)
}

func (a *adminAdapter) AdminGetImportedAPIKey(ctx context.Context, req *talosv2alpha1.GetImportedAPIKeyRequest) (*talosv2alpha1.ImportedAPIKey, error) {
	return a.svc.GetImportedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminDeleteImportedAPIKey(ctx context.Context, req *talosv2alpha1.DeleteImportedAPIKeyRequest) (*emptypb.Empty, error) {
	return a.svc.DeleteImportedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminUpdateIssuedAPIKey(ctx context.Context, req *talosv2alpha1.UpdateIssuedAPIKeyRequest) (*talosv2alpha1.IssuedAPIKey, error) {
	return a.svc.UpdateIssuedAPIKey(ctx, req)
}

func (a *adminAdapter) AdminUpdateImportedAPIKey(ctx context.Context, req *talosv2alpha1.UpdateImportedAPIKeyRequest) (*talosv2alpha1.ImportedAPIKey, error) {
	return a.svc.UpdateImportedAPIKey(ctx, req)
}

// AdminVerifyAPIKey verifies an admin-supplied credential by delegating to the
// shared verifier helper on Public. The endpoint itself is admin-only.
func (a *adminAdapter) AdminVerifyAPIKey(ctx context.Context, req *talosv2alpha1.VerifyAPIKeyRequest) (*talosv2alpha1.VerifyAPIKeyResponse, error) {
	return a.public.VerifyAPIKey(ctx, req)
}

// AdminBatchVerifyAPIKeys verifies admin-supplied credentials in batch by
// delegating to the shared verifier helper on Public. The endpoint itself
// is admin-only.
func (a *adminAdapter) AdminBatchVerifyAPIKeys(ctx context.Context, req *talosv2alpha1.BatchVerifyAPIKeysRequest) (*talosv2alpha1.BatchVerifyAPIKeysResponse, error) {
	return a.public.BatchVerifyAPIKeys(ctx, req)
}

// RevokeAPIKey is the proof-of-possession self-revocation variant. It delegates
// to Public so the credential holder can revoke their own key without admin
// privileges.
func (a *adminAdapter) RevokeAPIKey(ctx context.Context, req *talosv2alpha1.SelfRevokeAPIKeyRequest) (*talosv2alpha1.SelfRevokeAPIKeyResponse, error) {
	return a.public.RevokeAPIKey(ctx, req)
}

// adminOnlyAdapter exposes all Admin* methods but leaves RevokeAPIKey (the
// proof-of-possession variant) wired to the embedded UnimplementedAPIKeysServer,
// which returns codes.Unimplemented → HTTP 404. Used when the server runs in
// ModeAdmin.
type adminOnlyAdapter struct {
	talosv2alpha1.UnimplementedAPIKeysServer

	svc    *service.Admin
	public *service.Public
}

func (a *adminOnlyAdapter) AdminIssueAPIKey(ctx context.Context, req *talosv2alpha1.IssueAPIKeyRequest) (*talosv2alpha1.IssueAPIKeyResponse, error) {
	return a.svc.IssueAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminGetIssuedAPIKey(ctx context.Context, req *talosv2alpha1.GetIssuedAPIKeyRequest) (*talosv2alpha1.IssuedAPIKey, error) {
	return a.svc.GetIssuedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminRotateIssuedAPIKey(ctx context.Context, req *talosv2alpha1.RotateIssuedAPIKeyRequest) (*talosv2alpha1.RotateIssuedAPIKeyResponse, error) {
	return a.svc.RotateIssuedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminRevokeIssuedAPIKey(ctx context.Context, req *talosv2alpha1.RevokeIssuedAPIKeyRequest) (*emptypb.Empty, error) {
	return a.svc.RevokeIssuedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminRevokeImportedAPIKey(ctx context.Context, req *talosv2alpha1.RevokeImportedAPIKeyRequest) (*emptypb.Empty, error) {
	return a.svc.RevokeImportedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminListIssuedAPIKeys(ctx context.Context, req *talosv2alpha1.ListIssuedAPIKeysRequest) (*talosv2alpha1.ListIssuedAPIKeysResponse, error) {
	return a.svc.ListIssuedAPIKeys(ctx, req)
}

func (a *adminOnlyAdapter) AdminDeriveToken(ctx context.Context, req *talosv2alpha1.DeriveTokenRequest) (*talosv2alpha1.DeriveTokenResponse, error) {
	return a.svc.DeriveToken(ctx, req)
}

func (a *adminOnlyAdapter) GetJWKS(ctx context.Context, req *talosv2alpha1.GetJWKSRequest) (*talosv2alpha1.GetJWKSResponse, error) {
	return a.public.GetJWKS(ctx, req)
}

func (a *adminOnlyAdapter) AdminImportAPIKey(ctx context.Context, req *talosv2alpha1.ImportAPIKeyRequest) (*talosv2alpha1.ImportedAPIKey, error) {
	return a.svc.ImportAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminBatchImportAPIKeys(ctx context.Context, req *talosv2alpha1.BatchImportAPIKeysRequest) (*talosv2alpha1.BatchImportAPIKeysResponse, error) {
	return a.svc.BatchImportAPIKeys(ctx, req)
}

func (a *adminOnlyAdapter) AdminListImportedAPIKeys(ctx context.Context, req *talosv2alpha1.ListImportedAPIKeysRequest) (*talosv2alpha1.ListImportedAPIKeysResponse, error) {
	return a.svc.ListImportedAPIKeys(ctx, req)
}

func (a *adminOnlyAdapter) AdminGetImportedAPIKey(ctx context.Context, req *talosv2alpha1.GetImportedAPIKeyRequest) (*talosv2alpha1.ImportedAPIKey, error) {
	return a.svc.GetImportedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminDeleteImportedAPIKey(ctx context.Context, req *talosv2alpha1.DeleteImportedAPIKeyRequest) (*emptypb.Empty, error) {
	return a.svc.DeleteImportedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminUpdateIssuedAPIKey(ctx context.Context, req *talosv2alpha1.UpdateIssuedAPIKeyRequest) (*talosv2alpha1.IssuedAPIKey, error) {
	return a.svc.UpdateIssuedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminUpdateImportedAPIKey(ctx context.Context, req *talosv2alpha1.UpdateImportedAPIKeyRequest) (*talosv2alpha1.ImportedAPIKey, error) {
	return a.svc.UpdateImportedAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminVerifyAPIKey(ctx context.Context, req *talosv2alpha1.VerifyAPIKeyRequest) (*talosv2alpha1.VerifyAPIKeyResponse, error) {
	return a.public.VerifyAPIKey(ctx, req)
}

func (a *adminOnlyAdapter) AdminBatchVerifyAPIKeys(ctx context.Context, req *talosv2alpha1.BatchVerifyAPIKeysRequest) (*talosv2alpha1.BatchVerifyAPIKeysResponse, error) {
	return a.public.BatchVerifyAPIKeys(ctx, req)
}

// publicOnlyAdapter exposes RevokeAPIKey (the proof-of-possession variant) and
// GetJWKS (a public verification key endpoint per RFC 7517). All Admin*
// methods fall through to the embedded UnimplementedAPIKeysServer, which
// returns codes.Unimplemented → HTTP 404. Used when the server runs in
// ModePublic.
type publicOnlyAdapter struct {
	talosv2alpha1.UnimplementedAPIKeysServer

	public *service.Public
}

func (a *publicOnlyAdapter) RevokeAPIKey(ctx context.Context, req *talosv2alpha1.SelfRevokeAPIKeyRequest) (*talosv2alpha1.SelfRevokeAPIKeyResponse, error) {
	return a.public.RevokeAPIKey(ctx, req)
}

func (a *publicOnlyAdapter) GetJWKS(ctx context.Context, req *talosv2alpha1.GetJWKSRequest) (*talosv2alpha1.GetJWKSResponse, error) {
	return a.public.GetJWKS(ctx, req)
}

// NewAllInOneAdapter creates an adapter that wires every method: all Admin*
// operations and the proof-of-possession RevokeAPIKey. Used in ModeAllInOne.
func NewAllInOneAdapter(svc *service.Admin, public *service.Public) talosv2alpha1.APIKeysServer {
	return &adminAdapter{svc: svc, public: public}
}

// NewAdminOnlyAdapter creates an adapter that wires all Admin* methods but
// leaves RevokeAPIKey returning Unimplemented (→ HTTP 404). Used in ModeAdmin.
// public is still required because AdminVerifyAPIKey and
// AdminBatchVerifyAPIKeys delegate to it.
func NewAdminOnlyAdapter(svc *service.Admin, public *service.Public) talosv2alpha1.APIKeysServer {
	return &adminOnlyAdapter{svc: svc, public: public}
}

// NewPublicOnlyAdapter creates an adapter that wires RevokeAPIKey and GetJWKS.
// All Admin* methods return Unimplemented (→ HTTP 404). Used in ModePublic.
func NewPublicOnlyAdapter(public *service.Public) talosv2alpha1.APIKeysServer {
	return &publicOnlyAdapter{public: public}
}

// reviewed - @aeneasr - 2026-03-26
