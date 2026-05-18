// Package http provides gRPC-Gateway HTTP/REST server functionality.
package http

import (
	"bytes"
	"io"
	"regexp"
	"strconv"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/ory-corp/talos/internal/duration"
)

// maxRequestBodySize bounds the io.ReadAll in Decode to prevent unbounded
// memory allocation from oversized requests. 4 MiB is well above the largest
// legitimate gRPC-Gateway request body in this service and matches the gRPC
// default max message size.
const maxRequestBodySize = 4 << 20 // 4 MiB

// DurationAwareJSONPb is a custom marshaler that supports human-friendly duration
// formats (e.g., "1d", "1y6mo", "24h") in addition to protobuf format ("86400s").
type DurationAwareJSONPb struct {
	runtime.JSONPb
}

// NewDurationAwareJSONPb creates a new marshaler with extended duration support.
func NewDurationAwareJSONPb() *DurationAwareJSONPb {
	return &DurationAwareJSONPb{
		JSONPb: runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: true,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: true,
			},
		},
	}
}

// NewDecoder returns a decoder that rewrites human-friendly duration strings
// (e.g. "1d") into protobuf seconds before delegating to the embedded JSONPb.
func (m *DurationAwareJSONPb) NewDecoder(r io.Reader) runtime.Decoder {
	return &durationAwareDecoder{
		reader: r,
		jsonpb: &m.JSONPb,
	}
}

type durationAwareDecoder struct {
	reader io.Reader
	jsonpb *runtime.JSONPb
}

// durationFieldPattern matches "ttl" key-value pairs where the value is a duration string.
// Anchoring on "ttl" prevents false positives on other string fields (e.g. {"unit": "1m"}).
// The unit alternation is shared with duration.Parse via duration.UnitAlternation.
// Fractional coefficients (e.g. "1.5h") are matched so they reach duration.Parse and are
// converted via time.ParseDuration for standard Go units.
var durationFieldPattern = regexp.MustCompile(
	`("ttl"\s*:\s*)"(\d+(?:\.\d+)?(?:` + duration.UnitAlternation + `)(?:\d+(?:\.\d+)?(?:` + duration.UnitAlternation + `))*)"`,
)

func (d *durationAwareDecoder) Decode(v any) error {
	// Read up to maxRequestBodySize+1 bytes. Reading one byte past the limit
	// lets us detect oversized bodies without buffering the entire payload.
	lr := io.LimitReader(d.reader, maxRequestBodySize+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxRequestBodySize {
		return status.Errorf(codes.ResourceExhausted,
			"request body exceeds maximum allowed size of %d bytes", maxRequestBodySize)
	}

	converted := convertDurationStrings(data)
	newDecoder := d.jsonpb.NewDecoder(bytes.NewReader(converted))
	return newDecoder.Decode(v)
}

// convertDurationStrings rewrites ttl fields from extended duration format to protobuf seconds.
// Example: {"ttl": "1y"} -> {"ttl": "31536000s"}, {"ttl": "1d12h"} -> {"ttl": "129600s"}.
func convertDurationStrings(data []byte) []byte {
	return durationFieldPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		submatches := durationFieldPattern.FindSubmatch(match)
		if len(submatches) < 3 {
			return match
		}
		key := submatches[1]
		s := string(submatches[2])

		d, err := duration.Parse(s)
		if err != nil {
			return match
		}

		// FormatFloat preserves sub-second precision (e.g. 500ms -> "0.5s").
		seconds := d.Seconds()
		converted := strconv.FormatFloat(seconds, 'f', -1, 64) + "s"
		return append(key, []byte(`"`+converted+`"`)...)
	})
}

// reviewed - @aeneasr - 2026-03-26
