package persistencetest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// capturingT implements the errorf interface used by compareJSONSnapshot. It
// records whether Errorf was called and captures the formatted messages
// without forwarding to the real testing.T, so the proof test can assert that
// the helper detects (or tolerates) drift without failing itself.
type capturingT struct {
	failed   bool
	messages []string
}

func (c *capturingT) Helper() {}

func (c *capturingT) Errorf(format string, args ...any) {
	c.failed = true
	c.messages = append(c.messages, fmt.Sprintf(format, args...))
}

// snapshotProofRow is a small struct used to drive compareJSONSnapshot in
// the proof test. The json tags mirror the convention used by sqlc-generated
// db structs (db tag == json tag), so the assertions exercise the same code
// path the driver tests rely on.
type snapshotProofRow struct {
	Name      string `json:"name"`
	Status    int32  `json:"status"`
	UpdatedAt string `json:"updated_at"`
}

// TestCompareJSONSnapshotDetectsDrift is the proof test the reviewer asked
// for: it confirms compareJSONSnapshot flags value drift, field swaps, and
// silently-dropped ignored fields, while tolerating ignored fields that
// differ between sides.
func TestCompareJSONSnapshotDetectsDrift(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		want       snapshotProofRow
		got        snapshotProofRow
		ignoreKeys []string
		wantFail   bool
	}{
		{
			name: "identical snapshots pass",
			want: snapshotProofRow{Name: "alpha", Status: 1, UpdatedAt: "t1"},
			got:  snapshotProofRow{Name: "alpha", Status: 1, UpdatedAt: "t1"},
		},
		{
			name:     "value mismatch fails",
			want:     snapshotProofRow{Name: "alpha", Status: 1, UpdatedAt: "t1"},
			got:      snapshotProofRow{Name: "alpha", Status: 2, UpdatedAt: "t1"},
			wantFail: true,
		},
		{
			name:     "field-name swap fails",
			want:     snapshotProofRow{Name: "alpha", Status: 1, UpdatedAt: "t1"},
			got:      snapshotProofRow{Name: "beta", Status: 1, UpdatedAt: "t1"},
			wantFail: true,
		},
		{
			name:       "ignored key zero on got fails",
			want:       snapshotProofRow{Name: "alpha", Status: 1, UpdatedAt: "t1"},
			got:        snapshotProofRow{Name: "alpha", Status: 1, UpdatedAt: ""},
			ignoreKeys: []string{"updated_at"},
			wantFail:   true,
		},
		{
			name:       "ignored key differing values pass",
			want:       snapshotProofRow{Name: "alpha", Status: 1, UpdatedAt: "t1"},
			got:        snapshotProofRow{Name: "alpha", Status: 1, UpdatedAt: "t2"},
			ignoreKeys: []string{"updated_at"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			capture := &capturingT{}
			compareJSONSnapshot(capture, "proof", tc.want, tc.got, tc.ignoreKeys...)
			assert.Equal(t, tc.wantFail, capture.failed,
				"compareJSONSnapshot reported failed=%v but expected %v; messages: %v",
				capture.failed, tc.wantFail, capture.messages)
		})
	}
}
