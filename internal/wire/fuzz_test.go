package wire_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gmb-eudi/go-eudi-trust/internal/wire"
)

func seed(f *testing.F, name string) {
	f.Helper()
	//nolint:gosec // G304: name is always a compile-time constant fixture filename from this test file, never external input.
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "trust", name))
	if err != nil {
		f.Fatalf("seed %s: %v (regenerate with `go run ./testdata/gen`)", name, err)
	}
	f.Add(b)
}

func FuzzDecodeAnchors(f *testing.F) {
	seed(f, "anchors-pid-lv-v1.json")
	seed(f, "anchors-missing-notafter.json")
	f.Add([]byte(`{"snapshot":"x","generatedAt":"2026-07-01T06:00:00Z","anchors":[{}]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = wire.DecodeAnchors(data) // must not panic
	})
}

func FuzzDecodeSnapshot(f *testing.F) {
	seed(f, "snapshot.json")
	f.Add([]byte(`{"id":"x"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = wire.DecodeSnapshot(data) // must not panic
	})
}

func FuzzDecodeMatch(f *testing.F) {
	seed(f, "match-passed.json")
	f.Add([]byte(`{"verdict":"MAYBE"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = wire.DecodeMatch(data) // must not panic
	})
}
