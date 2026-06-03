package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"

	"github.com/ory/x/cmdx"

	client "github.com/ory/talos/internal/client/generated"
)

// registerListFlags adds the standard list/filter flags shared by issued and imported key commands.
func registerListFlags(cmd *cobra.Command, status, actorID *string, pageSize *int32, pageToken *string) {
	cmd.Flags().StringVar(status, "status", "", "Filter by status (KEY_STATUS_ACTIVE, KEY_STATUS_REVOKED, KEY_STATUS_EXPIRED)")
	cmd.Flags().StringVar(actorID, "actor", "", "Filter by actor ID")
	cmd.Flags().Int32Var(pageSize, "page-size", 0, "Number of items per page (default: 50, max: 1000)")
	cmd.Flags().StringVar(pageToken, "page-token", "", "Cursor token for pagination")
}

// buildListFilter constructs an AIP-160 filter expression from individual flag values.
func buildListFilter(actorID, status string) string {
	var parts []string
	if actorID != "" {
		parts = append(parts, fmt.Sprintf("actor_id=%q", actorID))
	}
	if status != "" {
		parts = append(parts, fmt.Sprintf("status=%s", status))
	}
	return strings.Join(parts, " AND ")
}

func newIssuedKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issued",
		Short: "Manage issued API keys",
		Long:  `Get, list, update, and rotate issued API keys.`,
	}

	cmdx.RegisterFormatFlags(cmd.PersistentFlags())

	cmd.AddCommand(newIssueAPIKeyCmd())
	cmd.AddCommand(newGetIssuedAPIKeyCmd())
	cmd.AddCommand(newListIssuedAPIKeysCmd())
	cmd.AddCommand(newUpdateIssuedAPIKeyCmd())
	cmd.AddCommand(newRotateIssuedAPIKeyCmd())
	cmd.AddCommand(newRevokeIssuedAPIKeyCmd())

	return cmd
}

func newRevokeIssuedAPIKeyCmd() *cobra.Command {
	return newRevokeAPIKeyCmd(revokeAPIKeyCmdConfig{
		short:          "Revoke an issued API key",
		successMessage: "Issued API key revoked.",
		revokeError:    "revoke issued API key",
		getError:       "get issued API key after revoke",
		revoke:         newRevokeIssuedAPIKeyRequest,
		get:            getIssuedAPIKeyAfterRevoke,
	})
}

func newRevokeIssuedAPIKeyRequest(ctx context.Context, api client.ApiKeysAPI, keyID string, reason client.RevocationReason, reasonText string) revokeAPIKeyRequest {
	body := client.AdminRevokeIssuedApiKeyBody{}
	setRevocationBody(&body, reason, reasonText)
	return api.AdminRevokeIssuedApiKey(ctx, keyID).AdminRevokeIssuedApiKeyBody(body)
}

func getIssuedAPIKeyAfterRevoke(ctx context.Context, api client.ApiKeysAPI, keyID string) (any, apiKeyLike, error) {
	return executeGetAPIKey(api.AdminGetIssuedApiKey(ctx, keyID))
}

//nolint:dupl // issued/imported get commands share structure but call different SDK methods.
func newGetIssuedAPIKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "get [key-id]",
		Short:        "Get details of an issued API key",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, httpResp, err := newSDKClient(serverAddr).ApiKeysAPI.
				AdminGetIssuedApiKey(ctx, keyID).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "get issued API key")
			}

			cmdx.PrintRow(cmd, apiKeyRow(resp, resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())

	return cmd
}

func newListIssuedAPIKeysCmd() *cobra.Command {
	var (
		status    string
		actorID   string
		pageSize  int32
		pageToken string
	)

	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List issued API keys",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			req := newSDKClient(serverAddr).ApiKeysAPI.
				AdminListIssuedApiKeys(ctx)

			if f := buildListFilter(actorID, status); f != "" {
				req = req.Filter(f)
			}
			if pageSize > 0 {
				req = req.PageSize(pageSize)
			}
			if pageToken != "" {
				req = req.PageToken(pageToken)
			}

			resp, httpResp, err := req.Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "list issued API keys")
			}

			nextToken := resp.GetNextPageToken()
			if nextToken != "" {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Next page token: %s\n", nextToken)
			}

			keys := resp.GetIssuedApiKeys()
			cmdx.PrintTable(cmd, issuedKeyListTable(keys, resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	registerListFlags(cmd, &status, &actorID, &pageSize, &pageToken)

	return cmd
}

func newUpdateIssuedAPIKeyCmd() *cobra.Command {
	var (
		name            string
		scopesStr       string
		metadataStr     string
		allowedCIDRs    string
		rateLimitQuota  int64
		rateLimitWindow string
		updateMask      string
	)

	cmd := &cobra.Command{
		Use:          "update [key-id]",
		Short:        "Update an issued API key",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			body := client.AdminUpdateIssuedApiKeyRequest{}

			anyChanged := false

			if cmd.Flags().Changed("name") {
				body.SetName(name)
				anyChanged = true
			}
			if cmd.Flags().Changed("scopes") {
				body.SetScopes(parseScopes(scopesStr))
				anyChanged = true
			}
			if cmd.Flags().Changed("metadata") {
				metadata, err := parseJSONMap(metadataStr, "metadata")
				if err != nil {
					return err
				}
				if metadata != nil {
					body.SetMetadata(metadata)
				}
				anyChanged = true
			}

			if cmd.Flags().Changed("allowed-cidrs") {
				ipRestriction := client.IPRestriction{}
				ipRestriction.SetAllowedCidrs(parseCIDRs(allowedCIDRs))
				body.SetIpRestriction(ipRestriction)
				anyChanged = true
			}

			if cmd.Flags().Changed("rate-limit-quota") {
				if rateLimitQuota > 0 {
					windowSeconds, err := parseDurationToSeconds(rateLimitWindow)
					if err != nil {
						return errors.Wrap(err, "invalid rate limit window")
					}
					body.SetRateLimitPolicy(buildRateLimitPolicy(rateLimitQuota, windowSeconds))
				} else {
					// Clear rate limit policy by setting an empty policy.
					body.SetRateLimitPolicy(client.RateLimitPolicy{})
				}
				anyChanged = true
			}

			useMask := cmd.Flags().Changed("update-mask")
			if !useMask && !anyChanged {
				return errors.New("at least one of --name, --scopes, --metadata, --allowed-cidrs, --rate-limit-quota, or --update-mask must be specified")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			req := newSDKClient(serverAddr).ApiKeysAPI.
				AdminUpdateIssuedApiKey(ctx, keyID).
				AdminUpdateIssuedApiKeyRequest(body)
			if useMask {
				req = req.UpdateMask(updateMask)
			}

			resp, httpResp, err := req.Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "update issued API key")
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "API key updated.")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())

			cmdx.PrintRow(cmd, apiKeyRow(resp, resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().StringVar(&name, "name", "", "New name for the API key")
	cmd.Flags().StringVar(&scopesStr, "scopes", "", "Comma-separated list of scopes")
	cmd.Flags().StringVar(&metadataStr, "metadata", "", "JSON metadata for the API key")
	cmd.Flags().StringVar(&allowedCIDRs, "allowed-cidrs", "", "Comma-separated CIDR ranges for IP restriction (empty string removes restrictions)")
	cmd.Flags().Int64Var(&rateLimitQuota, "rate-limit-quota", 0, "Maximum requests allowed per window (0 = no limit)")
	cmd.Flags().StringVar(&rateLimitWindow, "rate-limit-window", "", "Rate limit window duration (e.g., 60s, 5m)")
	cmd.Flags().StringVar(&updateMask, "update-mask", "", "Comma-separated AIP-134 field-mask paths (e.g., name,scopes). When set, the listed fields are written; fields omitted from the request body are cleared to their zero value.")

	return cmd
}

func newRotateIssuedAPIKeyCmd() *cobra.Command {
	var (
		name        string
		scopesStr   string
		metadataStr string
	)

	cmd := &cobra.Command{
		Use:          "rotate [key-id]",
		Short:        "Rotate an issued API key (revokes old key, creates new one)",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			body := client.AdminRotateIssuedApiKeyBody{}

			if cmd.Flags().Changed("name") {
				body.SetName(name)
			}
			if cmd.Flags().Changed("scopes") {
				body.SetScopes(parseScopes(scopesStr))
			}
			if cmd.Flags().Changed("metadata") {
				metadata, err := parseJSONMap(metadataStr, "metadata")
				if err != nil {
					return err
				}
				if metadata != nil {
					body.SetMetadata(metadata)
				}
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, httpResp, err := newSDKClient(serverAddr).ApiKeysAPI.
				AdminRotateIssuedApiKey(ctx, keyID).
				AdminRotateIssuedApiKeyBody(body).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "rotate issued API key")
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "API key rotated.")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "*** IMPORTANT: Save this API key securely, it will not be shown again! ***")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())

			cmdx.PrintRow(cmd, secretKeyRow(resp.GetIssuedApiKey(), resp.GetSecret(), resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().StringVar(&name, "name", "", "New name for the rotated API key")
	cmd.Flags().StringVar(&scopesStr, "scopes", "", "Comma-separated list of scopes for the rotated key")
	cmd.Flags().StringVar(&metadataStr, "metadata", "", "JSON metadata for the rotated key")

	return cmd
}

// reviewed - @aeneasr - 2026-03-25
