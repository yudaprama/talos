package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"

	"github.com/ory/x/cmdx"

	client "github.com/ory/talos/internal/client/generated"
)

// rawRow wraps any SDK type for cmdx.PrintRow.
// JSON/YAML output returns the raw SDK type via Interface().
// Table output uses the provided header/columns.
type rawRow struct {
	raw     any
	header  []string
	columns []string
}

func (r rawRow) Header() []string  { return r.header }
func (r rawRow) Columns() []string { return r.columns }
func (r rawRow) Interface() any    { return r.raw }

// rawTable wraps any SDK type for cmdx.PrintTable.
type rawTable struct {
	raw    any
	header []string
	rows   [][]string
}

func (t rawTable) Header() []string  { return t.header }
func (t rawTable) Table() [][]string { return t.rows }
func (t rawTable) Interface() any    { return t.raw }
func (t rawTable) Len() int          { return len(t.rows) }

// apiKeyColumns returns the standard table columns for an API key.
func apiKeyColumns(k apiKeyLike) []string {
	return []string{
		k.GetKeyId(), k.GetName(), k.GetActorId(),
		string(k.GetStatus()), strings.Join(k.GetScopes(), ", "),
	}
}

var apiKeyHeader = []string{"KEY ID", "NAME", "ACTOR ID", "STATUS", "SCOPES"}

// apiKeyRow builds a rawRow for any SDK type satisfying apiKeyLike.
func apiKeyRow(raw any, k apiKeyLike) rawRow {
	return rawRow{raw: raw, header: apiKeyHeader, columns: apiKeyColumns(k)}
}

// secretKeyRow builds a rawRow for responses that contain a key + secret (issue, rotate).
// raw is the original SDK response used for JSON/YAML output.
func secretKeyRow(issuedKey client.IssuedApiKey, secret string, raw any) rawRow {
	return rawRow{
		raw:     raw,
		header:  slices.Concat(apiKeyHeader, []string{"SECRET"}),
		columns: append(apiKeyColumns(&issuedKey), secret),
	}
}

// verifyRow builds a rawRow for a verify API key response.
func verifyRow(resp *client.VerifyApiKeyResponse) rawRow {
	return rawRow{
		raw:    resp,
		header: []string{"KEY ID", "IS VALID", "STATUS", "ACTOR ID", "SCOPES"},
		columns: []string{
			resp.GetKeyId(), strconv.FormatBool(resp.GetIsValid()),
			string(resp.GetStatus()),
			resp.GetActorId(), strings.Join(resp.GetScopes(), ", "),
		},
	}
}

// tokenRow builds a rawRow for a derive token response.
func tokenRow(resp *client.DeriveTokenResponse) rawRow {
	token := resp.GetToken()
	var expireTime string
	if t, ok := token.GetExpireTimeOk(); ok {
		expireTime = t.Format(time.RFC3339)
	}
	return rawRow{
		raw:    resp,
		header: []string{"TOKEN", "EXPIRE TIME"},
		columns: []string{
			token.GetToken(), expireTime,
		},
	}
}

// batchVerifyTable builds a rawTable for a batch verify response.
func batchVerifyTable(resp *client.BatchVerifyApiKeysResponse) rawTable {
	results := resp.GetResults()
	rows := make([][]string, len(results))
	for i, r := range results {
		var errStr string
		if r.GetErrorMessage() != "" {
			errStr = r.GetErrorMessage()
		}
		rows[i] = []string{
			r.GetKeyId(), strconv.FormatBool(r.GetIsValid()),
			string(r.GetStatus()),
			r.GetActorId(), strings.Join(r.GetScopes(), ", "), errStr,
		}
	}
	return rawTable{
		raw:    resp,
		header: []string{"KEY ID", "IS VALID", "STATUS", "ACTOR ID", "SCOPES", "ERROR"},
		rows:   rows,
	}
}

func newSDKClient(serverURL string) *client.APIClient {
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{{URL: serverURL}}
	return client.NewAPIClient(cfg)
}

type revokeAPIKeyCmdConfig struct {
	short          string
	successMessage string
	revokeError    string
	getError       string
	revoke         func(context.Context, client.ApiKeysAPI, string, client.RevocationReason, string) revokeAPIKeyRequest
	get            func(context.Context, client.ApiKeysAPI, string) (any, apiKeyLike, error)
}

type revokeAPIKeyRequest interface {
	Execute() (map[string]any, *http.Response, error)
}

type revocationBodySetter interface {
	SetReason(reason client.RevocationReason)
	SetDescription(description string)
}

func setRevocationBody(body revocationBodySetter, reason client.RevocationReason, reasonText string) {
	body.SetReason(reason)
	if reasonText != "" {
		body.SetDescription(reasonText)
	}
}

func closeAPIResponse(resp *http.Response) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}

func executeRevokeAPIKey(req revokeAPIKeyRequest) error {
	_, resp, err := req.Execute()
	closeAPIResponse(resp)
	return err
}

func executeGetAPIKey[T apiKeyLike, R interface {
	Execute() (T, *http.Response, error)
}](req R) (any, apiKeyLike, error) {
	apiKey, resp, err := req.Execute()
	closeAPIResponse(resp)
	return apiKey, apiKey, err
}

func newRevokeAPIKeyCmd(cfg revokeAPIKeyCmdConfig) *cobra.Command {
	var (
		reason     string
		reasonText string
	)

	cmd := &cobra.Command{
		Use:          "revoke [key-id]",
		Short:        cfg.short,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			reasonEnum, err := parseRevocationReason(reason)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			sdkClient := newSDKClient(serverAddr)
			if err := executeRevokeAPIKey(cfg.revoke(ctx, sdkClient.ApiKeysAPI, keyID, reasonEnum, reasonText)); err != nil {
				return failAPIError(cmd, err, cfg.revokeError)
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), cfg.successMessage)

			raw, apiKey, err := cfg.get(ctx, sdkClient.ApiKeysAPI, keyID)
			if err != nil {
				return failAPIError(cmd, err, cfg.getError)
			}

			cmdx.PrintRow(cmd, apiKeyRow(raw, apiKey))
			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for revocation (key_compromise, affiliation_changed, superseded, privilege_withdrawn)")
	cmd.Flags().StringVar(&reasonText, "reason-text", "", "Human-readable reason text")

	return cmd
}

// apiKeyLike is the common getter interface shared by IssuedApiKey and ImportedApiKey.
type apiKeyLike interface {
	GetKeyId() string
	GetName() string
	GetActorId() string
	GetScopes() []string
	GetStatus() client.KeyStatus
	GetExpireTimeOk() (*time.Time, bool)
}

// keyPolicySetter is the common setter interface for metadata, IP restrictions, and rate limit
// policies. Satisfied by IssueApiKeyRequest, ImportApiKeyRequest,
// AdminUpdateIssuedAPIKeyBody, and AdminRotateIssuedApiKeyBody.
type keyPolicySetter interface {
	SetMetadata(v map[string]any)
	SetIpRestriction(v client.IPRestriction)
	SetRateLimitPolicy(v client.RateLimitPolicy)
}

// applyKeyPolicies parses and applies optional metadata, IP restriction, and rate limit policy
// fields to any SDK request/body type that satisfies keyPolicySetter.
func applyKeyPolicies(dest keyPolicySetter, metadataStr, allowedCIDRs string, rateLimitQuota int64, rateLimitWindow string) error {
	metadata, err := parseJSONMap(metadataStr, "metadata")
	if err != nil {
		return err
	}
	if metadata != nil {
		dest.SetMetadata(metadata)
	}

	if cidrs := parseCIDRs(allowedCIDRs); cidrs != nil {
		ipRestriction := client.IPRestriction{}
		ipRestriction.SetAllowedCidrs(cidrs)
		dest.SetIpRestriction(ipRestriction)
	}

	if rateLimitQuota > 0 {
		windowSeconds, err := parseDurationToSeconds(rateLimitWindow)
		if err != nil {
			return errors.Wrap(err, "invalid rate limit window")
		}
		dest.SetRateLimitPolicy(buildRateLimitPolicy(rateLimitQuota, windowSeconds))
	} else if rateLimitWindow != "" {
		return errors.New("--rate-limit-window requires --rate-limit-quota to be set")
	}

	return nil
}

// rateLimitPolicySetter is satisfied by the issued and imported update request
// bodies, both of which expose SetRateLimitPolicy.
type rateLimitPolicySetter interface {
	SetRateLimitPolicy(v client.RateLimitPolicy)
}

// applyRateLimitUpdate sets the rate limit policy on an update body from the
// --rate-limit-quota and --rate-limit-window flags. It reports whether the body
// was modified.
//
// A rate limit policy is a full {quota, window} object, so a window alone is
// meaningless and the helper reads both flags together:
//
//   - quota > 0: set the policy from quota + window (window is required).
//   - only --rate-limit-window changed: error (window without quota is invalid).
//   - quota == 0: error (the server rejects a zero quota; clearing a policy is
//     done with --update-mask rate_limit_policy).
func applyRateLimitUpdate(cmd *cobra.Command, dest rateLimitPolicySetter, quota int64, window string) (bool, error) {
	quotaChanged := cmd.Flags().Changed("rate-limit-quota")
	windowChanged := cmd.Flags().Changed("rate-limit-window")
	if !quotaChanged && !windowChanged {
		return false, nil
	}
	if quota > 0 {
		windowSeconds, err := parseDurationToSeconds(window)
		if err != nil {
			return false, errors.Wrap(err, "invalid rate limit window")
		}
		dest.SetRateLimitPolicy(buildRateLimitPolicy(quota, windowSeconds))
		return true, nil
	}
	if !quotaChanged {
		return false, errors.New("--rate-limit-window requires --rate-limit-quota to be set")
	}
	return false, errors.New("--rate-limit-quota must be greater than 0; to remove a rate limit, run update with --update-mask rate_limit_policy")
}

// cmdEndpoint reads the --endpoint flag from the command.
func cmdEndpoint(cmd *cobra.Command) (string, error) {
	ep, err := cmd.Flags().GetString("endpoint")
	if err != nil {
		return "", errors.Wrap(err, "read endpoint flag")
	}
	return ep, nil
}

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage API keys",
		Long:  `Create, list, get, revoke, and rotate API keys.`,
	}

	cmdx.RegisterFormatFlags(cmd.PersistentFlags())

	cmd.AddCommand(newIssueAPIKeyCmd())
	cmd.AddCommand(newDeriveTokenCmd())
	cmd.AddCommand(newVerifyAPIKeyCmd())
	cmd.AddCommand(newSelfRevokeAPIKeyCmd())
	cmd.AddCommand(newBatchVerifyAPIKeysCmd())
	cmd.AddCommand(newIssuedKeysCmd())
	cmd.AddCommand(newImportedKeysCmd())

	return cmd
}

func parseTokenAlgorithm(algorithm string) (client.TokenAlgorithm, error) {
	switch strings.ToLower(algorithm) {
	case "jwt":
		return client.TOKENALGORITHM_TOKEN_ALGORITHM_JWT, nil
	case "macaroon":
		return client.TOKENALGORITHM_TOKEN_ALGORITHM_MACAROON, nil
	default:
		return "", errors.Errorf("invalid algorithm: %s (must be 'jwt' or 'macaroon')", algorithm)
	}
}

func parseScopes(scopesStr string) []string {
	if scopesStr == "" {
		return nil
	}
	scopes := strings.Split(scopesStr, ",")
	for i := range scopes {
		scopes[i] = strings.TrimSpace(scopes[i])
	}

	return scopes
}

func parseTTL(ttlStr string) (string, error) {
	if ttlStr == "" {
		return "", nil
	}

	_, err := time.ParseDuration(ttlStr)
	if err != nil {
		return "", errors.Errorf("invalid TTL duration '%s': %s (examples: '24h', '168h', '30m')", ttlStr, err)
	}

	return ttlStr, nil
}

func parseCIDRs(cidrsStr string) []string {
	if cidrsStr == "" {
		return nil
	}
	cidrs := strings.Split(cidrsStr, ",")
	for i := range cidrs {
		cidrs[i] = strings.TrimSpace(cidrs[i])
	}
	return cidrs
}

func parseJSONMap(jsonStr, fieldName string) (map[string]any, error) {
	if jsonStr == "" {
		return nil, nil
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, errors.Wrapf(err, "invalid %s JSON", fieldName)
	}

	return data, nil
}

func newIssueAPIKeyCmd() *cobra.Command {
	var (
		actorID         string
		scopesStr       string
		ttl             time.Duration
		metadataStr     string
		allowedCIDRs    string
		rateLimitQuota  int64
		rateLimitWindow string
	)

	cmd := &cobra.Command{
		Use:          "issue [name]",
		Short:        "Issue a new API key",
		Aliases:      []string{"create"},
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			req := client.IssueApiKeyRequest{}
			req.SetName(name)
			req.SetActorId(actorID)
			req.SetScopes(parseScopes(scopesStr))
			req.SetTtl(ttl.String())

			if err := applyKeyPolicies(&req, metadataStr, allowedCIDRs, rateLimitQuota, rateLimitWindow); err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, httpResp, err := newSDKClient(serverAddr).ApiKeysAPI.
				AdminIssueApiKey(ctx).
				IssueApiKeyRequest(req).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "create API key")
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "API key issued.")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "*** IMPORTANT: Save this API key securely, it will not be shown again! ***")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())

			cmdx.PrintRow(cmd, secretKeyRow(resp.GetIssuedApiKey(), resp.GetSecret(), resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().StringVar(&actorID, "actor", "", "Actor ID (required)")
	cmd.Flags().StringVar(&scopesStr, "scopes", "", "Comma-separated list of scopes")
	cmd.Flags().DurationVar(&ttl, "ttl", time.Hour*24, "Time-to-live duration (e.g., '24h', '168h')")
	cmd.Flags().StringVar(&metadataStr, "metadata", "", "JSON metadata for the API key")
	cmd.Flags().StringVar(&allowedCIDRs, "allowed-cidrs", "", "Comma-separated CIDR ranges for IP restriction (e.g., '10.0.0.0/8,192.168.0.0/16')")
	cmd.Flags().Int64Var(&rateLimitQuota, "rate-limit-quota", 0, "Maximum requests allowed per window (0 = no limit)")
	cmd.Flags().StringVar(&rateLimitWindow, "rate-limit-window", "", "Rate limit window duration (e.g., 60s, 5m)")
	_ = cmd.MarkFlagRequired("actor")

	return cmd
}

func newDeriveTokenCmd() *cobra.Command {
	var (
		ttlStr       string
		algorithmStr string
		claimsStr    string
	)

	cmd := &cobra.Command{
		Use:          "derive-token [api-key-token]",
		Short:        "Derive a new derived token from an existing API key",
		Long:         `Derives a new short-lived derived token from an existing opaque API key. The output will be a JWT or Macaroon token.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			apiKeyToken := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			req := client.DeriveTokenRequest{}
			req.SetCredential(apiKeyToken)

			if algorithmStr != "" {
				algorithm, err := parseTokenAlgorithm(algorithmStr)
				if err != nil {
					return err
				}
				req.SetAlgorithm(algorithm)
			}

			if ttlStr != "" {
				ttl, err := parseTTL(ttlStr)
				if err != nil {
					return err
				}
				req.SetTtl(ttl)
			}

			customClaims, err := parseJSONMap(claimsStr, "custom claims")
			if err != nil {
				return err
			}
			if customClaims != nil {
				req.SetCustomClaims(customClaims)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, httpResp, err := newSDKClient(serverAddr).ApiKeysAPI.
				AdminDeriveToken(ctx).
				DeriveTokenRequest(req).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "derive token")
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Token derived.")
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())

			cmdx.PrintRow(cmd, tokenRow(resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().StringVar(&ttlStr, "ttl", "1h", "Token time-to-live duration")
	cmd.Flags().StringVar(&algorithmStr, "algorithm", "jwt", "Algorithm for derived token (jwt or macaroon)")
	cmd.Flags().StringVar(&claimsStr, "claims", "", "Custom claims as JSON (e.g., '{\"user_ip\":\"192.168.1.1\",\"request_id\":\"abc123\"}'). Reserved claims like iss, sub, exp cannot be overridden.")

	return cmd
}

func newVerifyAPIKeyCmd() *cobra.Command {
	var noCache bool

	cmd := &cobra.Command{
		Use:          "verify [credential]",
		Short:        "Verify a credential (API key or token)",
		Long:         `Verifies a credential against the server. Checks if the credential is active, not expired, and not revoked.`,
		Aliases:      []string{"validate"},
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			credential := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			req := client.VerifyApiKeyRequest{}
			req.SetCredential(credential)

			sdkClient := newSDKClient(serverAddr)
			if noCache {
				sdkClient.GetConfig().AddDefaultHeader("Cache-Control", "no-cache")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, httpResp, err := sdkClient.ApiKeysAPI.
				AdminVerifyApiKey(ctx).
				VerifyApiKeyRequest(req).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "verify API key")
			}

			// Format errors mean the credential itself is malformed; no useful
			// response body to display — just report the cause and exit.
			if resp.GetErrorCode() == client.VERIFICATIONERRORCODE_VERIFICATION_ERROR_INVALID_FORMAT {
				return errors.Newf("invalid API key format: %s", resp.GetErrorMessage())
			}

			if resp.GetIsValid() {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "API key is VALID")
				_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			} else {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "API key is INVALID")
				_, _ = fmt.Fprintln(cmd.ErrOrStderr())
			}

			cmdx.PrintRow(cmd, verifyRow(resp))

			if !resp.GetIsValid() {
				return cmdx.FailSilently(cmd)
			}

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "Bypass verification cache (sends Cache-Control: no-cache header)")

	return cmd
}

func newSelfRevokeAPIKeyCmd() *cobra.Command {
	var reason string

	cmd := &cobra.Command{
		Use:          "self-revoke [credential]",
		Short:        "Revoke an API key using the credential itself as proof",
		Long:         "Self-revokes an API key by presenting the full credential as proof of ownership. Does not require admin access.",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			credential := args[0]
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			reasonEnum, err := parseRevocationReason(reason)
			if err != nil {
				return err
			}

			req := client.SelfRevokeApiKeyRequest{}
			req.SetCredential(credential)
			req.SetReason(reasonEnum)

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			_, httpResp, err := newSDKClient(serverAddr).ApiKeysAPI.
				RevokeApiKey(ctx).
				SelfRevokeApiKeyRequest(req).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "self-revoke API key")
			}

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "API key self-revoked.")

			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "Reason for revocation")

	return cmd
}

func newBatchVerifyAPIKeysCmd() *cobra.Command {
	var noCache bool

	cmd := &cobra.Command{
		Use:          "batch-verify [credentials...]",
		Short:        "Verify multiple credentials in a single request",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			serverAddr, err := cmdEndpoint(cmd)
			if err != nil {
				return err
			}

			requests := make([]client.VerifyApiKeyRequest, len(args))
			for i, cred := range args {
				req := client.VerifyApiKeyRequest{}
				req.SetCredential(cred)
				requests[i] = req
			}

			batchReq := client.BatchVerifyApiKeysRequest{}
			batchReq.SetRequests(requests)

			sdkClient := newSDKClient(serverAddr)
			if noCache {
				sdkClient.GetConfig().AddDefaultHeader("Cache-Control", "no-cache")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()

			resp, httpResp, err := sdkClient.ApiKeysAPI.
				AdminBatchVerifyApiKeys(ctx).
				BatchVerifyApiKeysRequest(batchReq).
				Execute()
			if httpResp != nil {
				defer httpResp.Body.Close()
			}
			if err != nil {
				return failAPIError(cmd, err, "batch verify API keys")
			}

			cmdx.PrintTable(cmd, batchVerifyTable(resp))

			return nil
		},
	}

	cmdx.RegisterFormatFlags(cmd.Flags())
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "Bypass verification cache (sends Cache-Control: no-cache header)")

	return cmd
}

// parseDurationToSeconds parses a Go duration string and returns the number of seconds.
func parseDurationToSeconds(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("rate limit window is required when quota is set")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, errors.Wrapf(err, "invalid duration %q (examples: '60s', '5m', '1h')", s)
	}
	seconds := int64(d.Seconds())
	if seconds <= 0 {
		return 0, errors.Errorf("rate limit window must be positive, got %q", s)
	}
	return seconds, nil
}

// buildRateLimitPolicy creates a RateLimitPolicy from quota and window values.
func buildRateLimitPolicy(quota int64, windowSeconds int64) client.RateLimitPolicy {
	policy := client.RateLimitPolicy{}
	policy.SetQuota(strconv.FormatInt(quota, 10))
	policy.SetWindow(strconv.FormatInt(windowSeconds, 10) + "s")
	return policy
}

func parseRevocationReason(s string) (client.RevocationReason, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	if normalized == "" {
		return client.REVOCATIONREASON_REVOCATION_REASON_UNSPECIFIED, nil
	}

	// Support both snake_case ("key_compromise") and full enum names
	// ("revocation_reason_key_compromise")
	switch normalized {
	case "key_compromise", "revocation_reason_key_compromise":
		return client.REVOCATIONREASON_REVOCATION_REASON_KEY_COMPROMISE, nil
	case "affiliation_changed", "revocation_reason_affiliation_changed":
		return client.REVOCATIONREASON_REVOCATION_REASON_AFFILIATION_CHANGED, nil
	case "superseded", "revocation_reason_superseded":
		return client.REVOCATIONREASON_REVOCATION_REASON_SUPERSEDED, nil
	case "privilege_withdrawn", "revocation_reason_privilege_withdrawn":
		return client.REVOCATIONREASON_REVOCATION_REASON_PRIVILEGE_WITHDRAWN, nil
	case "unspecified", "revocation_reason_unspecified":
		return client.REVOCATIONREASON_REVOCATION_REASON_UNSPECIFIED, nil
	default:
		return "", errors.Errorf("unknown revocation reason %q (valid: key_compromise, affiliation_changed, superseded, privilege_withdrawn)", s)
	}
}

// reviewed - @aeneasr - 2026-03-25
