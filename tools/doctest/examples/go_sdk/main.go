// Package main provides an executable Go SDK example for Talos API operations.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cockroachdb/errors"

	client "github.com/ory/talos/internal/client/generated"
)

var (
	errTalosURLNotSet = errors.New("TALOS_URL not set")
	errJWTNotActive   = errors.New("JWT should be active")
)

func run() error {
	talosURL := os.Getenv("TALOS_URL")
	if talosURL == "" {
		return errTalosURLNotSet
	}

	ctx := context.Background()

	// region: init-client
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{
		{URL: talosURL},
	}
	c := client.NewAPIClient(cfg)
	// endregion: init-client

	fmt.Println("=== Issue API Key ===")
	// region: issue-key
	issueResp, _, err := c.ApiKeysAPI.
		AdminIssueApiKey(ctx).
		IssueApiKeyRequest(client.IssueApiKeyRequest{
			Name:    new("my-service"),
			ActorId: new("user_123"),
			Scopes:  []string{"read", "write"},
			Ttl:     new("720h"),
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("issue key: %w", err)
	}

	// Secret is only available at creation time
	issuedKey := issueResp.GetIssuedApiKey()
	fmt.Println("Key ID:", issuedKey.GetKeyId())
	fmt.Println("Secret:", issueResp.GetSecret())
	// endregion: issue-key

	secret := issueResp.GetSecret()
	keyID := issuedKey.GetKeyId()

	fmt.Println("\n=== Verify Key ===")
	// region: verify-key
	verifyResp, _, err := c.ApiKeysAPI.
		AdminVerifyApiKey(ctx).
		VerifyApiKeyRequest(client.VerifyApiKeyRequest{
			Credential: new(secret),
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("verify key: %w", err)
	}

	if verifyResp.GetIsValid() {
		fmt.Println("Key is valid, owner:", verifyResp.GetActorId())
	} else {
		fmt.Println("Key is invalid:", verifyResp.GetErrorMessage())
	}
	// endregion: verify-key

	fmt.Println("\n=== Batch Verify ===")
	// region: batch-verify
	batchResp, _, err := c.ApiKeysAPI.
		AdminBatchVerifyApiKeys(ctx).
		BatchVerifyApiKeysRequest(client.BatchVerifyApiKeysRequest{
			Requests: []client.VerifyApiKeyRequest{
				{Credential: new(secret)},
				{Credential: new("invalid-key-for-testing")},
			},
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("batch verify: %w", err)
	}

	for i, result := range batchResp.GetResults() {
		fmt.Printf("Key %d: is_valid=%v\n", i, result.GetIsValid())
	}
	// endregion: batch-verify

	fmt.Println("\n=== Derive JWT ===")
	// region: derive-jwt
	algorithm := client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT
	deriveResp, _, err := c.ApiKeysAPI.
		AdminDeriveToken(ctx).
		DeriveTokenRequest(client.DeriveTokenRequest{
			Credential: new(secret),
			Algorithm:  &algorithm,
			Ttl:        new("1h"),
			Scopes:     []string{"read"},
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("derive token: %w", err)
	}

	derivedToken := deriveResp.GetToken()
	fmt.Println("JWT:", derivedToken.GetToken())
	// endregion: derive-jwt

	jwt := derivedToken.GetToken()

	// Verify the derived JWT (not shown in docs, just validates the flow)
	fmt.Println("\n=== Verify JWT ===")
	jwtVerifyResp, _, err := c.ApiKeysAPI.
		AdminVerifyApiKey(ctx).
		VerifyApiKeyRequest(client.VerifyApiKeyRequest{
			Credential: new(jwt),
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("verify jwt: %w", err)
	}

	if jwtVerifyResp.GetIsValid() {
		fmt.Printf("JWT is valid, owner: %s\n", jwtVerifyResp.GetActorId())
	} else {
		return errors.Wrapf(errJWTNotActive, "got error: %s", jwtVerifyResp.GetErrorMessage())
	}

	fmt.Println("\n=== Revoke Key ===")
	// region: revoke-key
	reason := client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE
	_, _, err = c.ApiKeysAPI.
		AdminRevokeIssuedApiKey(ctx, keyID).
		AdminRevokeIssuedApiKeyBody(client.AdminRevokeIssuedApiKeyBody{
			Reason: &reason,
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("revoke key: %w", err)
	}
	fmt.Println("Key revoked successfully")
	// endregion: revoke-key

	fmt.Println("\n=== Error Handling ===")
	// region: error-handling
	_, httpResp, err := c.ApiKeysAPI.
		AdminGetIssuedApiKey(ctx, "nonexistent-id").
		Execute()
	if err != nil {
		var apiErr *client.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			var status struct {
				Code    int32  `json:"code"`
				Message string `json:"message"`
				Details []struct {
					Type     string            `json:"@type"`
					Reason   string            `json:"reason"`
					Domain   string            `json:"domain"`
					Metadata map[string]string `json:"metadata"`
				} `json:"details"`
			}
			if jsonErr := json.Unmarshal(apiErr.Body(), &status); jsonErr == nil {
				fmt.Println("gRPC code:", status.Code)           // 5 = NOT_FOUND
				fmt.Println("HTTP status:", httpResp.StatusCode) // 404
				fmt.Println("Message:", status.Message)
				for _, d := range status.Details {
					if strings.HasSuffix(d.Type, "ErrorInfo") {
						fmt.Println("Reason:", d.Reason) // Stable; switch on this
					}
				}
			}
		}
	}
	// endregion: error-handling

	fmt.Println("\nAll operations completed successfully.")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
