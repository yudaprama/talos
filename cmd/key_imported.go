package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"

	"github.com/ory/x/cmdx"

	client "github.com/ory/talos/internal/client/generated"
)

const batchImportTimeout = 2 * time.Minute

// issuedKeyListTable builds a rawTable for a list of issued API keys.
func issuedKeyListTable(keys []client.IssuedAPIKey, raw any) rawTable {
	rows := make([][]string, len(keys))
	for i := range keys {
		k := &keys[i]
		rows[i] = []string{
			k.GetKeyId(), k.GetName(), k.GetActorId(),
			string(k.GetStatus()), strings.Join(k.GetScopes(), ", "),
		}
	}
	return rawTable{
		raw:    raw,
		header: []string{"KEY ID", "NAME", "ACTOR ID", "STATUS", "SCOPES"},
		rows:   rows,
	}
}

// importedKeyListTable builds a rawTable for a list of imported API keys.
func importedKeyListTable(keys []client.ImportedAPIKey, raw any) rawTable {
	rows := make([][]string, len(keys))
	for i := range keys {
		k := &keys[i]
		rows[i] = []string{
			k.GetKeyId(), k.GetName(), k.GetActorId(),
			string(k.GetStatus()), strings.Join(k.GetScopes(), ", "),
		}
	}
	return rawTable{
		raw:    raw,
		header: []string{"KEY ID", "NAME", "ACTOR ID", "STATUS", "SCOPES"},
		rows:   rows,
	}
}

// batchImportTable builds a rawTable from a batch import response.
func batchImportTable(resp *client.BatchImportAPIKeysResponse) rawTable {
	results := resp.GetResults()
	rows := make([][]string, len(results))
	for i, item := range results {
		var keyID, name, status, errorColumn string
		status = "failed"

		if apiKey, ok := item.GetImportedApiKeyOk(); ok {
			keyID = apiKey.GetKeyId()
			name = apiKey.GetName()
			status = "success"
		} else {
			if errorCode, ok := item.GetErrorCodeOk(); ok {
				errorColumn = string(*errorCode)
			}
			if errorMessage, ok := item.GetErrorMessageOk(); ok {
				if errorColumn != "" {
					errorColumn += ": " + *errorMessage
				} else {
					errorColumn = *errorMessage
				}
			}
		}

		rows[i] = []string{
			fmt.Sprintf("%d", item.GetIndex()),
			keyID, name, status, errorColumn,
		}
	}
	return rawTable{
		raw:    resp,
		header: []string{"INDEX", "KEY ID", "NAME", "STATUS", "ERROR"},
		rows:   rows,
	}
}

type deleteOutput struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

func (o deleteOutput) Header() []string {
	return []string{"ID", "Deleted"}
}

func (o deleteOutput) Columns() []string {
	deleted := "false"
	if o.Deleted {
		deleted = "true"
	}
	return []string{o.ID, deleted}
}

func (o deleteOutput) Interface() any {
	return o
}

func newImportedKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "imported",
		Short: "Manage imported API keys",
		Long:  `Import, list, get, update, revoke, and delete externally-created API keys.`,
	}

	cmdx.RegisterFormatFlags(cmd.PersistentFlags())

	cmd.AddCommand(newImportAPIKeyCmd())
	cmd.AddCommand(newBatchImportAPIKeysCmd())
	cmd.AddCommand(newGetImportedAPIKeyCmd())
	cmd.AddCommand(newListImportedAPIKeysCmd())
	cmd.AddCommand(newUpdateImportedAPIKeyCmd())
	cmd.AddCommand(newRevokeImportedAPIKeyCmd())
	cmd.AddCommand(newDeleteImportedAPIKeyCmd())

	return cmd
}

func newImportAPIKeyCmd() *cobra.Command {
	var (
		rawKey          string
		actorID         string
		scopesStr       string
		ttlStr          string
		metadataStr     string
		allowedCIDRs    string
		rateLimitQuota  int64
		rateLimitWindow string
	)

	cmd := &cobra.Command{
		Use:          "import [name]",
		Short:        "Import an external API key",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			req := client.ImportAPIKeyRequest{}
			req.SetName(name)
			req.SetRawKey(rawKey)
			req.SetActorId(actorID)

			scopes := parseScopes(scopesStr)
			if scopes != nil {
				req.SetScopes(scopes)
			}

			ttl, err := parseTTL(ttlStr)
			if err != nil {
				return err
			}
			if ttl != "" {
				req.SetTtl(ttl)
			}

			if err := applyKeyPolicies(&req, metadataStr, allowedCIDRs, rateLimitQuota, rateLimitWindow); err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, httpResp, err := newSDKClient(serverAddr).APIKeysAPI.
				AdminImportAPIKey(ctx).
				ImportAPIKeyRequest(req).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "import API key")
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "API key imported.")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())

			cmdx.PrintRow(cmd, apiKeyRow(resp, resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().StringVar(&rawKey, "raw-key", "", "The raw key string to import (required)")
	cmd.Flags().StringVar(&actorID, "actor", "", "Actor ID (required)")
	cmd.Flags().StringVar(&scopesStr, "scopes", "", "Comma-separated list of scopes")
	cmd.Flags().StringVar(&ttlStr, "ttl", "", "Time-to-live duration (e.g., '24h', '8760h')")
	cmd.Flags().StringVar(&metadataStr, "metadata", "", "JSON metadata for the imported key")
	cmd.Flags().StringVar(&allowedCIDRs, "allowed-cidrs", "", "Comma-separated CIDR ranges for IP restriction (e.g., '10.0.0.0/8,192.168.0.0/16')")
	cmd.Flags().Int64Var(&rateLimitQuota, "rate-limit-quota", 0, "Maximum requests allowed per window (0 = no limit)")
	cmd.Flags().StringVar(&rateLimitWindow, "rate-limit-window", "", "Rate limit window duration (e.g., 60s, 5m)")
	_ = cmd.MarkFlagRequired("raw-key")
	_ = cmd.MarkFlagRequired("actor")

	return cmd
}

func newBatchImportAPIKeysCmd() *cobra.Command {
	var filePath string

	cmd := &cobra.Command{
		Use:          "batch-import --file keys.json",
		Short:        "Batch import API keys from a JSON file",
		Long:         "Batch import API keys from a JSON file. Each request is limited to 1000 keys; the server rejects batches that exceed this limit.",
		Aliases:      []string{"import-batch"},
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			keys, err := readBatchImportRequests(cmd, filePath)
			if err != nil {
				return err
			}
			// Server enforces MaxBatchImportSize (1000 keys per request); see internal/service/limits.go.
			req := client.NewBatchImportAPIKeysRequest()
			req.SetRequests(keys)

			ctx, cancel := context.WithTimeout(cmd.Context(), batchImportTimeout)
			defer cancel()

			resp, httpResp, err := newSDKClient(serverAddr).APIKeysAPI.
				AdminBatchImportAPIKeys(ctx).
				BatchImportAPIKeysRequest(*req).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "batch import API keys")
			}

			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Imported %d keys (%d failed).\n", resp.GetSuccessCount(), resp.GetFailureCount())
			if len(resp.GetResults()) > 0 {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			}

			cmdx.PrintTable(cmd, batchImportTable(resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().StringVar(&filePath, "file", "", "Path to JSON file with key array, or '-' for stdin")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func readBatchImportRequests(cmd *cobra.Command, filePath string) ([]client.ImportAPIKeyRequest, error) {
	var (
		raw []byte
		err error
	)

	switch filePath {
	case "-":
		raw, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, errors.Wrap(err, "read batch import input from stdin")
		}
	case "":
		return nil, errors.New("file path is required")
	default:
		// #nosec G304 -- CLI intentionally reads a user-provided local path.
		raw, err = os.ReadFile(filePath)
		if err != nil {
			return nil, errors.Wrapf(err, "read batch import file: %s", filePath)
		}
	}

	var keys []client.ImportAPIKeyRequest
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, errors.Wrap(err, "parse batch import JSON")
	}

	return keys, nil
}

//nolint:dupl // imported/issued get commands share structure but call different SDK methods.
func newGetImportedAPIKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "get [key-id]",
		Short:        "Get details of an imported API key",
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

			resp, httpResp, err := newSDKClient(serverAddr).APIKeysAPI.
				AdminGetImportedAPIKey(ctx, keyID).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "get imported API key")
			}

			cmdx.PrintRow(cmd, apiKeyRow(resp, resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())

	return cmd
}

func newListImportedAPIKeysCmd() *cobra.Command {
	var (
		status    string
		actorID   string
		pageSize  int32
		pageToken string
	)

	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List imported API keys",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			req := newSDKClient(serverAddr).APIKeysAPI.
				AdminListImportedAPIKeys(ctx)

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
				return failAPIError(cmd, err, "list imported API keys")
			}

			nextToken := resp.GetNextPageToken()
			if nextToken != "" {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Next page token: %s\n", nextToken)
			}

			keys := resp.GetImportedApiKeys()
			cmdx.PrintTable(cmd, importedKeyListTable(keys, resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	registerListFlags(cmd, &status, &actorID, &pageSize, &pageToken)

	return cmd
}

func newUpdateImportedAPIKeyCmd() *cobra.Command {
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
		Short:        "Update an imported API key",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			body := client.AdminUpdateImportedAPIKeyRequest{}

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

			req := newSDKClient(serverAddr).APIKeysAPI.
				AdminUpdateImportedAPIKey(ctx, keyID).
				AdminUpdateImportedAPIKeyRequest(body)
			if useMask {
				req = req.UpdateMask(updateMask)
			}

			resp, httpResp, err := req.Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "update imported API key")
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "API key updated.")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())

			cmdx.PrintRow(cmd, apiKeyRow(resp, resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().StringVar(&name, "name", "", "New name for the imported API key")
	cmd.Flags().StringVar(&scopesStr, "scopes", "", "Comma-separated list of scopes")
	cmd.Flags().StringVar(&metadataStr, "metadata", "", "JSON metadata for the imported API key")
	cmd.Flags().StringVar(&allowedCIDRs, "allowed-cidrs", "", "Comma-separated CIDR ranges for IP restriction (empty string removes restrictions)")
	cmd.Flags().Int64Var(&rateLimitQuota, "rate-limit-quota", 0, "Maximum requests allowed per window (0 = no limit)")
	cmd.Flags().StringVar(&rateLimitWindow, "rate-limit-window", "", "Rate limit window duration (e.g., 60s, 5m)")
	cmd.Flags().StringVar(&updateMask, "update-mask", "", "Comma-separated AIP-134 field-mask paths (e.g., name,scopes). When set, the listed fields are written; fields omitted from the request body are cleared to their zero value.")

	return cmd
}

func newRevokeImportedAPIKeyCmd() *cobra.Command {
	return newRevokeAPIKeyCmd(revokeAPIKeyCmdConfig{
		short:          "Revoke an imported API key",
		successMessage: "Imported API key revoked.",
		revokeError:    "revoke imported API key",
		getError:       "get imported API key after revoke",
		revoke:         newRevokeImportedAPIKeyRequest,
		get:            getImportedAPIKeyAfterRevoke,
	})
}

func newRevokeImportedAPIKeyRequest(ctx context.Context, api client.APIKeysAPI, keyID string, reason client.RevocationReason, reasonText string) revokeAPIKeyRequest {
	body := client.AdminRevokeImportedAPIKeyBody{}
	setRevocationBody(&body, reason, reasonText)
	return api.AdminRevokeImportedAPIKey(ctx, keyID).AdminRevokeImportedAPIKeyBody(body)
}

func getImportedAPIKeyAfterRevoke(ctx context.Context, api client.APIKeysAPI, keyID string) (any, apiKeyLike, error) {
	return executeGetAPIKey(api.AdminGetImportedAPIKey(ctx, keyID))
}

func newDeleteImportedAPIKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "delete [key-id]",
		Short:        "Permanently delete an imported API key",
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

			_, httpResp, err := newSDKClient(serverAddr).APIKeysAPI.
				AdminDeleteImportedAPIKey(ctx, keyID).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "delete imported API key")
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Imported API key deleted.")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())

			output := deleteOutput{
				ID:      keyID,
				Deleted: true,
			}

			cmdx.PrintRow(cmd, output)

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())

	return cmd
}

// reviewed - @aeneasr - 2026-03-25
