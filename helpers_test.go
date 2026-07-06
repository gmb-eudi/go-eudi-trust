package trust_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// t0 is the injected wall-clock start of every test in this package.
var t0 = time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	//nolint:gosec // G304: name is always a compile-time constant fixture filename from this test file, never external input.
	b, err := os.ReadFile(filepath.Join("testdata", "trust", name))
	if err != nil {
		t.Fatalf("fixture %s: %v (regenerate with `go run ./testdata/gen`)", name, err)
	}
	return b
}

// fakeClock is a mutable injected time source (docs/conventions.md: inject
// clocks into anything validating validity windows).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(start time.Time) *fakeClock { return &fakeClock{t: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fixtureHandler replays a recorded /v1/anchors.json fixture with the real
// service's header semantics (references/trust-anchor/repo/routes/anchors.go):
// strong quoted ETag == snapshot id, X-Trust-Snapshot, X-Trust-Stale, and
// If-None-Match → 304 with headers but no body. Swap the served fixture via
// SetFile to simulate a snapshot replacement (withdrawal).
type fixtureHandler struct {
	t    *testing.T
	mu   sync.Mutex
	file string
	// LastQuery/LastHeader record the most recent request for assertions.
	LastQuery  string
	LastHeader http.Header
}

func newFixtureHandler(t *testing.T, file string) *fixtureHandler {
	return &fixtureHandler{t: t, file: file}
}

func (h *fixtureHandler) SetFile(file string) {
	h.mu.Lock()
	h.file = file
	h.mu.Unlock()
}

func (h *fixtureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	file := h.file
	h.LastQuery = r.URL.RawQuery
	h.LastHeader = r.Header.Clone()
	h.mu.Unlock()

	body := fixture(h.t, file)
	var probe struct {
		Snapshot string `json:"snapshot"`
		Stale    bool   `json:"stale"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		h.t.Fatalf("fixture %s is not valid JSON: %v", file, err)
	}
	w.Header().Set("ETag", `"`+probe.Snapshot+`"`)
	w.Header().Set("X-Trust-Snapshot", probe.Snapshot)
	w.Header().Set("X-Trust-Stale", strconv.FormatBool(probe.Stale))
	if inm := r.Header.Get("If-None-Match"); inm != "" &&
		strings.Trim(strings.TrimSpace(inm), `"`) == probe.Snapshot {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// lastQuery/lastHeader read the recorded request under the lock (the write
// happens in the server goroutine — direct field reads would race).
func (h *fixtureHandler) lastQuery() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.LastQuery
}

func (h *fixtureHandler) lastHeader() http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.LastHeader
}

// newFixtureServer returns a server plus its handler for later SetFile swaps.
func newFixtureServer(t *testing.T, file string) (*httptest.Server, *fixtureHandler) {
	t.Helper()
	h := newFixtureHandler(t, file)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, h
}

func mustUnmarshal(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}
