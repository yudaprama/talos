// Package duration provides extended duration parsing for API TTL fields.
// It supports human-friendly units (y, mo, w, d) in addition to all standard
// Go duration units (h, m, s, ms, us, µs, ns). Compound values like "1y6mo"
// and "1d12h30m" are accepted.
//
// Approximations (calendar precision is not required for API key TTLs):
//   - 1y  = 365 * 24h = 8760h
//   - 1mo = 30  * 24h = 720h
//   - 1w  = 7   * 24h = 168h
//   - 1d  = 24h
package duration

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

// ErrInvalidDuration is returned when Parse receives a malformed duration string.
var ErrInvalidDuration = errors.New("invalid duration")

// UnitAlternation is the regex alternation for all supported duration units,
// ordered longest-first to prevent prefix ambiguity (mo before m, ms before m/s).
// Used by both this package and the HTTP marshaler to keep the unit lists in sync.
const UnitAlternation = `y|mo|w|d|h|ms|µs|us|ns|m|s`

// extendedUnitPattern detects the presence of any extended unit (y, mo, w, d) in the string.
var extendedUnitPattern = regexp.MustCompile(`\d(y|mo|w|d)`)

// unitPattern matches a single (integer)(unit) pair at the start of a string.
var unitPattern = regexp.MustCompile(`^(\d+)(` + UnitAlternation + `)`)

// maxDuration caps the result to ~292 years, the maximum representable time.Duration.
const maxDuration = time.Duration(math.MaxInt64)

// Parse parses a duration string supporting extended units (y, mo, w, d) and
// all standard Go units (h, m, s, ms, us, µs, ns). Compound values such as
// "1y6mo", "1d12h", and "1h30m" are supported.
//
// For strings that contain only standard Go units, Parse delegates to
// time.ParseDuration, which supports fractional coefficients (e.g. "1.5h").
// Extended units use integer coefficients only.
//
// Unlike time.ParseDuration, the bare string "0" is not accepted — a unit is
// always required (e.g. "0s").
func Parse(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("%w: %q: empty string", ErrInvalidDuration, s)
	}

	// No extended units — delegate to time.ParseDuration, which supports
	// fractional coefficients like "1.5h" and handles all standard Go units.
	if !extendedUnitPattern.MatchString(s) {
		if s == "0" {
			return 0, fmt.Errorf("%w: %q: bare zero without unit", ErrInvalidDuration, s)
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("%w: %q: %w", ErrInvalidDuration, s, err)
		}
		return d, nil
	}

	remaining := s
	var total time.Duration
	for remaining != "" {
		m := unitPattern.FindStringSubmatch(remaining)
		if m == nil {
			return 0, fmt.Errorf("%w: %q: unexpected characters %q", ErrInvalidDuration, s, remaining)
		}
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %q: coefficient %q out of range", ErrInvalidDuration, s, m[1])
		}
		var unit time.Duration
		switch m[2] {
		case "y":
			unit = 365 * 24 * time.Hour
		case "mo":
			unit = 30 * 24 * time.Hour
		case "w":
			unit = 7 * 24 * time.Hour
		case "d":
			unit = 24 * time.Hour
		case "h":
			unit = time.Hour
		case "m":
			unit = time.Minute
		case "s":
			unit = time.Second
		case "ms":
			unit = time.Millisecond
		case "us", "µs":
			unit = time.Microsecond
		case "ns":
			unit = time.Nanosecond
		}
		component := time.Duration(n) * unit
		// Detect overflow: if n > 0 and the multiplication wrapped negative,
		// or if adding to total would overflow.
		if n > 0 && component/unit != time.Duration(n) {
			return 0, fmt.Errorf("%w: %q: value exceeds maximum representable duration", ErrInvalidDuration, s)
		}
		if total > maxDuration-component {
			return 0, fmt.Errorf("%w: %q: value exceeds maximum representable duration", ErrInvalidDuration, s)
		}
		total += component
		remaining = remaining[len(m[0]):]
	}
	return total, nil
}
