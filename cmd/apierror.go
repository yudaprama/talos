package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ory/x/cmdx"

	client "github.com/ory-corp/talos/internal/client/generated"
)

// failAPIError prints a human-readable error to stderr (extracting the server's JSON body when
// the error comes from the generated SDK), then silences cobra's default error printing and
// usage output. It always returns cmdx.ErrNoPrintButFail so main.go can suppress the
// duplicate print.
//
// Convention: two-layer error printing contract
//
//   - SilenceErrors: true on the root command means cobra never prints errors itself.
//   - main.go prints any error returned from Execute() that is NOT cmdx.ErrNoPrintButFail.
//   - API-calling commands (e.g., key create, key revoke) use failAPIError to format the
//     server response body into a readable message, print it to stderr, then return
//     cmdx.ErrNoPrintButFail — preventing main.go from printing a duplicate (bare) error.
//   - Local-operation commands (e.g., jwk generate) return raw errors directly from RunE;
//     main.go prints them verbatim. These commands have no server body to decode, so the
//     extra formatting step is unnecessary.
func failAPIError(cmd *cobra.Command, err error, context string) error {
	var msg string
	if apiErr, ok := errors.AsType[*client.GenericOpenAPIError](err); ok {
		msg = parseAPIErrorBody(apiErr.Body())
	}
	if msg == "" {
		msg = err.Error()
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s: %s\n", context, msg)
	return cmdx.FailSilently(cmd)
}

// parseAPIErrorBody extracts the human-readable message from a herodot error response body.
// Returns empty string when the body cannot be parsed.
func parseAPIErrorBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var payload struct {
		Error struct {
			Message string `json:"message"`
			Reason  string `json:"reason"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return string(body)
	}
	switch {
	case payload.Error.Message != "" && payload.Error.Reason != "":
		return fmt.Sprintf("%s (reason: %s)", payload.Error.Message, payload.Error.Reason)
	case payload.Error.Message != "":
		return payload.Error.Message
	case payload.Error.Reason != "":
		return payload.Error.Reason
	default:
		return string(body)
	}
}

// reviewed - @aeneasr - 2026-03-25
