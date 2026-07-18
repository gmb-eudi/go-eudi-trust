// Command gen regenerates the recorded trust-service fixtures in
// testdata/trust/ (D:/verifier/testdata/README.md rule: synthetic vectors
// must be reproducible from a generator). Run from the repo root:
//
//	go run ./testdata/gen
//
// Snapshot ids, timestamps and TL metadata are fixed constants asserted by
// the golden tests; the certificates are freshly generated synthetic ECDSA
// P-256 self-signed CAs — never production PKI material.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/gmb-eudi/go-eudi-trust/internal/wire"
)

const (
	snapV1        = "3f7a1c9e5b2d8f4a6c0e2b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a"
	snapV2        = "a1d3f5b7c9e1a3d5f7b9c1e3a5d7f9b1c3e5a7d9f1b3c5e7a9d1f3b5c7e9a1d3"
	statusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	// Mock-contract EUDI service-type URIs (extension E1): confirm against
	// CID (EU) 2025/2164 when E1 lands upstream; recorded in SOURCE.md.
	svcTypePID    = "http://uri.etsi.org/TrstSvc/Svctype/EUDI/PIDProvider"
	svcTypeAccess = "http://uri.etsi.org/TrstSvc/Svctype/EUDI/AccessCA"
)

var (
	generatedAt = time.Date(2026, 7, 1, 6, 0, 0, 0, time.UTC)
	notBefore   = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter    = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	dir := filepath.Join("testdata", "trust")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ca1, err := newCA("LV PID Provider CA 1", "LV")
	if err != nil {
		return err
	}
	ca2, err := newCA("LV PID Provider CA 2", "LV")
	if err != nil {
		return err
	}
	caEU, err := newCA("EU Wallet Access CA", "EU")
	if err != nil {
		return err
	}

	pid1 := anchor(ca1, "LV", "Latvia PID Provider", "PID Provider CA", svcTypePID, 42)
	pid2 := anchor(ca2, "LV", "Latvia PID Provider", "PID Provider CA 2", svcTypePID, 42)
	acc := anchor(caEU, "EU", "EU Wallet Infrastructure", "Wallet Access CA", svcTypeAccess, 7)

	files := map[string]any{
		// v1: two PID-provider anchors for LV.
		"anchors-pid-lv-v1.json": wire.AnchorsResponse{
			Snapshot: snapV1, GeneratedAt: generatedAt, Stale: false,
			Anchors: []wire.Anchor{pid1, pid2},
		},
		// v2: CA 2 withdrawn — snapshot replacement (changed ETag) carries
		// the complete new set.
		"anchors-pid-lv-v2.json": wire.AnchorsResponse{
			Snapshot: snapV2, GeneratedAt: generatedAt.Add(6 * time.Hour), Stale: false,
			Anchors: []wire.Anchor{pid1},
		},
		// EU-level list (wallet Access-CA LoTE), territory "EU".
		"anchors-accessca-eu.json": wire.AnchorsResponse{
			Snapshot: snapV1, GeneratedAt: generatedAt, Stale: false,
			Anchors: []wire.Anchor{acc},
		},
		// Upstream degraded: X-Trust-Stale / body stale = true.
		"anchors-stale.json": wire.AnchorsResponse{
			Snapshot: snapV1, GeneratedAt: generatedAt, Stale: true,
			Anchors: []wire.Anchor{pid1},
		},
	}
	for name, v := range files {
		if err := writeJSON(filepath.Join(dir, name), v); err != nil {
			return err
		}
	}

	// Contract-violation fixture: a valid anchor with notAfter (valid_until)
	// removed — missing valid_until = error.
	b, err := json.Marshal(wire.AnchorsResponse{
		Snapshot: snapV1, GeneratedAt: generatedAt, Anchors: []wire.Anchor{pid1},
	})
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	delete(m["anchors"].([]any)[0].(map[string]any), "notAfter")
	return writeJSON(filepath.Join(dir, "anchors-missing-notafter.json"), m)
}

func newCA(cn, country string) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Country:      []string{country},
			Organization: []string{"WP-06 synthetic fixture"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func anchor(cert *x509.Certificate, territory, tsp, svc, svcType string, tlSeq int64) wire.Anchor {
	sum := sha256.Sum256(cert.Raw)
	return wire.Anchor{
		Territory:          territory,
		Source:             "tl",
		TSPName:            tsp,
		ServiceName:        svc,
		ServiceType:        svcType,
		Status:             statusGranted,
		StatusStartingTime: notBefore,
		CertDER:            cert.Raw,
		FingerprintSHA256:  hex.EncodeToString(sum[:]),
		Subject:            cert.Subject.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		QCWithQSCD:         false,
		TLSequence:         tlSeq,
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
