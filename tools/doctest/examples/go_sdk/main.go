// Package main provides an executable Go SDK example for Talos API operations.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/cockroachdb/errors"

	client "github.com/ory-corp/talos/internal/client/generated"
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
	issueResp, _, err := c.APIKeysAPI.
		AdminIssueAPIKey(ctx).
		IssueAPIKeyRequest(client.IssueAPIKeyRequest{
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
	verifyResp, _, err := c.APIKeysAPI.
		AdminVerifyAPIKey(ctx).
		VerifyAPIKeyRequest(client.VerifyAPIKeyRequest{
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
	batchResp, _, err := c.APIKeysAPI.
		AdminBatchVerifyAPIKeys(ctx).
		BatchVerifyAPIKeysRequest(client.BatchVerifyAPIKeysRequest{
			Requests: []client.VerifyAPIKeyRequest{
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
	deriveResp, _, err := c.APIKeysAPI.
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
	jwtVerifyResp, _, err := c.APIKeysAPI.
		AdminVerifyAPIKey(ctx).
		VerifyAPIKeyRequest(client.VerifyAPIKeyRequest{
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
	_, _, err = c.APIKeysAPI.
		AdminRevokeAPIKey(ctx, keyID).
		AdminRevokeAPIKeyBody(client.AdminRevokeAPIKeyBody{
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
	_, httpResp, err := c.APIKeysAPI.
		AdminGetIssuedAPIKey(ctx, "nonexistent-id").
		Execute()
	if err != nil {
		if httpResp != nil {
			fmt.Println("HTTP status:", httpResp.StatusCode)
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
