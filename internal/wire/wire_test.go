package wire_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gmb-eudi/go-eudi-trust/internal/wire"
)

const (
	snapV1        = "3f7a1c9e5b2d8f4a6c0e2b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a"
	snapV2        = "a1d3f5b7c9e1a3d5f7b9c1e3a5d7f9b1c3e5a7d9f1b3c5e7a9d1f3b5c7e9a1d3"
	statusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	svcTypePID    = "http://uri.etsi.org/TrstSvc/Svctype/EUDI/PIDProvider"
	svcTypeAccess = "http://uri.etsi.org/TrstSvc/Svctype/EUDI/AccessCA"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	//nolint:gosec // G304: name is always a compile-time constant fixture filename from this test file, never external input.
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "trust", name))
	if err != nil {
		t.Fatalf("fixture %s: %v (regenerate with `go run ./testdata/gen`)", name, err)
	}
	return b
}

// mutate round-trips a valid fixture through map[string]any and applies fn —
// used to build contract-violation bodies from the golden fixture.
func mutate(t *testing.T, valid []byte, fn func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(valid, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func firstAnchor(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	anchors, ok := m["anchors"].([]any)
	if !ok || len(anchors) == 0 {
		t.Fatal("fixture has no anchors array")
	}
	a, ok := anchors[0].(map[string]any)
	if !ok {
		t.Fatal("anchors[0] is not an object")
	}
	return a
}

// DTO golden tests: decoded fields match the recorded
// fixtures, certificates parse, recomputed fingerprints match.
func TestDecodeAnchorsGolden(t *testing.T) {
	tests := []struct {
		name        string
		file        string
		snapshot    string
		stale       bool
		anchorCount int
		territory   string
		tlSequence  int64
		serviceType string
	}{
		{"pid_lv_v1", "anchors-pid-lv-v1.json", snapV1, false, 2, "LV", 42, svcTypePID},
		{"pid_lv_v2_after_withdrawal", "anchors-pid-lv-v2.json", snapV2, false, 1, "LV", 42, svcTypePID},
		{"access_ca_eu_level", "anchors-accessca-eu.json", snapV1, false, 1, "EU", 7, svcTypeAccess},
		{"stale_flagged", "anchors-stale.json", snapV1, true, 1, "LV", 42, svcTypePID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := wire.DecodeAnchors(fixture(t, tt.file))
			if err != nil {
				t.Fatalf("DecodeAnchors: %v", err)
			}
			if resp.Snapshot != tt.snapshot {
				t.Errorf("Snapshot = %q, want %q", resp.Snapshot, tt.snapshot)
			}
			if resp.Stale != tt.stale {
				t.Errorf("Stale = %v, want %v", resp.Stale, tt.stale)
			}
			if resp.GeneratedAt.IsZero() {
				t.Error("GeneratedAt is zero")
			}
			if len(resp.Anchors) != tt.anchorCount {
				t.Fatalf("len(Anchors) = %d, want %d", len(resp.Anchors), tt.anchorCount)
			}
			for i := range resp.Anchors {
				a := &resp.Anchors[i]
				cert, err := a.Certificate()
				if err != nil {
					t.Fatalf("anchor %d: Certificate(): %v", i, err)
				}
				sum := sha256.Sum256(cert.Raw)
				if got := hex.EncodeToString(sum[:]); got != a.FingerprintSHA256 {
					t.Errorf("anchor %d: recomputed fingerprint %s != %s", i, got, a.FingerprintSHA256)
				}
				if a.Territory != tt.territory {
					t.Errorf("anchor %d: Territory = %q, want %q", i, a.Territory, tt.territory)
				}
				if a.Status != statusGranted {
					t.Errorf("anchor %d: Status = %q, want %q", i, a.Status, statusGranted)
				}
				if a.ServiceType != tt.serviceType {
					t.Errorf("anchor %d: ServiceType = %q, want %q", i, a.ServiceType, tt.serviceType)
				}
				if a.TLSequence != tt.tlSequence {
					t.Errorf("anchor %d: TLSequence = %d, want %d", i, a.TLSequence, tt.tlSequence)
				}
				if !a.NotAfter.After(a.NotBefore) {
					t.Errorf("anchor %d: NotAfter %v not after NotBefore %v", i, a.NotAfter, a.NotBefore)
				}
				if a.Source != "tl" {
					t.Errorf("anchor %d: Source = %q, want tl", i, a.Source)
				}
				if !strings.Contains(a.Subject, "CN=") {
					t.Errorf("anchor %d: Subject %q missing CN", i, a.Subject)
				}
			}
		})
	}
}

// Contract strictness (missing valid_until = error).
// Negative tests — these MUST fail before wire.go exists and MUST pass after.
func TestDecodeAnchorsRejectsContractViolations(t *testing.T) {
	valid := fixture(t, "anchors-pid-lv-v1.json")
	tests := []struct {
		name string
		body []byte
	}{
		{"missing_notAfter_valid_until", fixture(t, "anchors-missing-notafter.json")},
		{"empty_body", nil},
		{"not_json", []byte("<html>bad gateway</html>")},
		{"missing_snapshot_id", mutate(t, valid, func(m map[string]any) { delete(m, "snapshot") })},
		{"missing_generatedAt", mutate(t, valid, func(m map[string]any) { delete(m, "generatedAt") })},
		{"missing_certDer", mutate(t, valid, func(m map[string]any) { delete(firstAnchor(t, m), "certDer") })},
		{"certDer_not_a_certificate", mutate(t, valid, func(m map[string]any) {
			firstAnchor(t, m)["certDer"] = "bm90IGEgY2VydGlmaWNhdGU=" // base64("not a certificate")
		})},
		{"fingerprint_mismatch", mutate(t, valid, func(m map[string]any) {
			firstAnchor(t, m)["fingerprintSha256"] = strings.Repeat("0", 64)
		})},
		{"missing_status", mutate(t, valid, func(m map[string]any) { delete(firstAnchor(t, m), "status") })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := wire.DecodeAnchors(tt.body); !errors.Is(err, wire.ErrInvalid) {
				t.Fatalf("DecodeAnchors err = %v, want wire.ErrInvalid", err)
			}
		})
	}
}

// Additive-evolution tolerance: unknown fields must NOT be rejected — the
// upstream API evolves additively (trust-service API contract, E1–E3).
func TestDecodeAnchorsToleratesUnknownFields(t *testing.T) {
	body := mutate(t, fixture(t, "anchors-pid-lv-v1.json"), func(m map[string]any) {
		m["futureField"] = "x"
		firstAnchor(t, m)["anotherFutureField"] = 7
	})
	if _, err := wire.DecodeAnchors(body); err != nil {
		t.Fatalf("unknown fields must be tolerated, got %v", err)
	}
}

// Extension E2 (trust-service API contract): useCases is optional
// per-anchor metadata (accredited EAA use cases). Present decodes verbatim
// in order; absent decodes as nil — never an error, never a forced non-nil
// empty slice.
func TestDecodeAnchorsUseCases(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		body := mutate(t, fixture(t, "anchors-pid-lv-v1.json"), func(m map[string]any) {
			firstAnchor(t, m)["useCases"] = []any{"pharmacy", "age_verification"}
		})
		resp, err := wire.DecodeAnchors(body)
		if err != nil {
			t.Fatalf("DecodeAnchors: %v", err)
		}
		want := []string{"pharmacy", "age_verification"}
		if !reflect.DeepEqual(resp.Anchors[0].UseCases, want) {
			t.Errorf("Anchors[0].UseCases = %#v, want %#v", resp.Anchors[0].UseCases, want)
		}
	})
	t.Run("absent", func(t *testing.T) {
		resp, err := wire.DecodeAnchors(fixture(t, "anchors-pid-lv-v1.json"))
		if err != nil {
			t.Fatalf("DecodeAnchors: %v", err)
		}
		if resp.Anchors[0].UseCases != nil {
			t.Errorf("Anchors[0].UseCases = %#v, want nil", resp.Anchors[0].UseCases)
		}
	})
}

func TestDecodeSnapshotGolden(t *testing.T) {
	resp, err := wire.DecodeSnapshot(fixture(t, "snapshot.json"))
	if err != nil {
		t.Fatalf("DecodeSnapshot: %v", err)
	}
	if resp.ID != snapV1 {
		t.Errorf("ID = %q, want %q", resp.ID, snapV1)
	}
	if resp.LOTLSequence != 351 {
		t.Errorf("LOTLSequence = %d, want 351", resp.LOTLSequence)
	}
	if want := time.Date(2026, 7, 1, 6, 0, 0, 0, time.UTC); !resp.GeneratedAt.Equal(want) {
		t.Errorf("GeneratedAt = %v, want %v", resp.GeneratedAt, want)
	}
	if len(resp.Territories) != 2 {
		t.Fatalf("len(Territories) = %d, want 2", len(resp.Territories))
	}
	lv, ee := resp.Territories[0], resp.Territories[1]
	if lv.Code != "LV" || lv.TLSequence != 42 || lv.Stale || lv.AnchorCount != 2 {
		t.Errorf("LV territory = %+v", lv)
	}
	if ee.Code != "EE" || !ee.Stale || !ee.CarriedOver || ee.AnchorCount != 5 {
		t.Errorf("EE territory = %+v", ee)
	}
	if len(resp.PendingBootstrap) == 0 {
		t.Error("PendingBootstrap should be present in the fixture")
	}
	if len(resp.Pending) != 0 {
		t.Errorf("Pending = %d entries, want 0", len(resp.Pending))
	}
}

func TestDecodeSnapshotRejects(t *testing.T) {
	valid := fixture(t, "snapshot.json")
	tests := []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"not_json", []byte("nope")},
		{"missing_id", mutate(t, valid, func(m map[string]any) { delete(m, "id") })},
		{"missing_generatedAt", mutate(t, valid, func(m map[string]any) { delete(m, "generatedAt") })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := wire.DecodeSnapshot(tt.body); !errors.Is(err, wire.ErrInvalid) {
				t.Fatalf("err = %v, want wire.ErrInvalid", err)
			}
		})
	}
}

func TestDecodeMatchGolden(t *testing.T) {
	tests := []struct {
		file    string
		verdict string
	}{
		{"match-passed.json", "PASSED"},
		{"match-failed.json", "FAILED"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			resp, err := wire.DecodeMatch(fixture(t, tt.file))
			if err != nil {
				t.Fatalf("DecodeMatch: %v", err)
			}
			if resp.Verdict != tt.verdict {
				t.Errorf("Verdict = %q, want %q", resp.Verdict, tt.verdict)
			}
			if resp.Snapshot != snapV1 {
				t.Errorf("Snapshot = %q, want %q", resp.Snapshot, snapV1)
			}
			if resp.CheckedAt.IsZero() {
				t.Error("CheckedAt is zero")
			}
			if len(resp.Checks) == 0 {
				t.Error("Checks raw payload missing")
			}
		})
	}
}

// Unknown verdict = reject, never fall through (fail-closed analog of
// "unknown status-list format").
func TestDecodeMatchRejects(t *testing.T) {
	valid := fixture(t, "match-passed.json")
	tests := []struct {
		name string
		body []byte
	}{
		{"unknown_verdict", mutate(t, valid, func(m map[string]any) { m["verdict"] = "MAYBE" })},
		{"missing_verdict", mutate(t, valid, func(m map[string]any) { delete(m, "verdict") })},
		{"missing_snapshot", mutate(t, valid, func(m map[string]any) { delete(m, "snapshot") })},
		{"missing_checkedAt", mutate(t, valid, func(m map[string]any) { delete(m, "checkedAt") })},
		{"not_json", []byte("x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := wire.DecodeMatch(tt.body); !errors.Is(err, wire.ErrInvalid) {
				t.Fatalf("err = %v, want wire.ErrInvalid", err)
			}
		})
	}
}
