package validation

import (
	"regexp"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"

	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

// ListFilter holds parsed filter values extracted from an AIP-160 filter string.
type ListFilter struct {
	ActorID string
	Status  talosv2alpha1.KeyStatus
}

// reAND splits on the AND keyword (case-insensitive) surrounded by whitespace.
var reAND = regexp.MustCompile(`(?i)\s+AND\s+`)

// reClause matches a single filter clause: field="quoted" or field=UNQUOTED_WORD.
var reClause = regexp.MustCompile(`^(\w+)\s*=\s*(?:"([^"]+)"|([\w.-]+))$`)

// ParseListFilter parses an AIP-160 list filter string into structured filter values.
//
// SQL injection safety: this parser is immune to SQL injection for the following reasons:
//  1. Field names are validated against an allowlist (actor_id, status). Unknown fields are rejected.
//  2. Values are never interpolated into SQL strings. They are passed as parameterized query
//     arguments to the database driver, which handles escaping.
//  3. The reClause regex constrains expression shape to field=value or field="value" only.
//     Quoted values match [^"]+ (no embedded quotes); unquoted values match [\w.-]+ (alphanumeric,
//     dot, hyphen only). This prevents injection of SQL operators, semicolons, or comments.
//  4. The actor_id value is length-capped at 256 characters.
//  5. The status field is validated against the KeyStatus enum allowlist (exact match required).
//
// Supported expressions:
//
//	actor_id="user_123"
//	status=KEY_STATUS_ACTIVE
//	actor_id="user_123" AND status=KEY_STATUS_ACTIVE
func ParseListFilter(filter string) (ListFilter, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return ListFilter{}, nil
	}

	var f ListFilter
	clauses := reAND.Split(filter, -1)

	for _, raw := range clauses {
		clause := strings.TrimSpace(raw)
		if clause == "" {
			return ListFilter{}, errors.New("empty clause in filter")
		}

		m := reClause.FindStringSubmatch(clause)
		if m == nil {
			return ListFilter{}, errors.Newf("invalid filter expression: %q", clause)
		}
		field := m[1]
		value := m[3]
		if value == "" {
			value = m[2]
		}

		switch field {
		case "actor_id":
			if f.ActorID != "" {
				return ListFilter{}, errors.Newf("duplicate filter field %q", field)
			}
			if len(value) > 256 {
				return ListFilter{}, errors.New("actor_id value exceeds maximum length of 256 characters")
			}
			f.ActorID = value
		case "status":
			if f.Status != talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED {
				return ListFilter{}, errors.Newf("duplicate filter field %q", field)
			}
			val, ok := talosv2alpha1.KeyStatus_value[value]
			if !ok {
				return ListFilter{}, errors.Newf("invalid status value %q: must be %s", value, validKeyStatusList())
			}
			if val == 0 {
				return ListFilter{}, errors.Newf("KEY_STATUS_UNSPECIFIED is not a valid filter value; use a specific status like KEY_STATUS_ACTIVE or KEY_STATUS_REVOKED")
			}
			f.Status = talosv2alpha1.KeyStatus(val)
		default:
			return ListFilter{}, errors.Newf("unsupported filter field %q: supported fields are actor_id and status", field)
		}
	}

	return f, nil
}

// validKeyStatusList returns the supported KeyStatus enum names as a human-
// readable list, excluding KEY_STATUS_UNSPECIFIED. The list is sorted by the
// enum's numeric value so the output stays stable as new statuses are added.
func validKeyStatusList() string {
	vals := make([]int32, 0, len(talosv2alpha1.KeyStatus_name))
	for v := range talosv2alpha1.KeyStatus_name {
		if v == int32(talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED) {
			continue
		}
		vals = append(vals, v)
	}
	slices.Sort(vals)

	names := make([]string, 0, len(vals))
	for _, v := range vals {
		names = append(names, talosv2alpha1.KeyStatus_name[v])
	}
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	case 2:
		return names[0] + " or " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + ", or " + names[len(names)-1]
	}
}

// reviewed - @aeneasr - 2026-03-26
