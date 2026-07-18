package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
)

// ---- synthetic PKI (generated in-test, never committed) ----

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serialCounter int64 = 1

func nextSerial() *big.Int {
	serialCounter++
	return big.NewInt(serialCounter)
}

// newTestCA creates a self-signed CA valid t0±1y.
func newTestCA(t *testing.T, cn, country string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := caTemplate(cn, country)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func caTemplate(cn, country string) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             t0.Add(-365 * 24 * time.Hour),
		NotAfter:              t0.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if country != "" {
		tmpl.Subject.Country = []string{country}
	}
	return tmpl
}

// issueCA issues a subordinate CA (for intermediate-chain tests).
func (ca *testCA) issueCA(t *testing.T, cn, country string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := caTemplate(cn, country)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

// issueLeaf issues an end-entity document-signer certificate; returns DER
// and the leaf key.
func (ca *testCA) issueLeaf(t *testing.T, cn, country string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    t0.Add(-30 * 24 * time.Hour),
		NotAfter:     t0.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if country != "" {
		tmpl.Subject.Country = []string{country}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// ---- stub AnchorSource with injected clock ----

type stubSource struct {
	anchors map[string][]trust.Anchor // key: "<type>|<country>"
	err     error
	now     time.Time
	calls   []string
}

func (s *stubSource) AnchorsFor(t trust.AnchorType, country string) ([]trust.Anchor, error) {
	key := string(t) + "|" + country
	s.calls = append(s.calls, key)
	if s.err != nil {
		return nil, fmt.Errorf("stub: %w", s.err)
	}
	return s.anchors[key], nil
}

// Now implements the optional clock interface ResolveIssuerKey discovers.
func (s *stubSource) Now() time.Time { return s.now }

func sourceWith(typ trust.AnchorType, country string, cas ...*testCA) *stubSource {
	anchors := make([]trust.Anchor, 0, len(cas))
	for _, ca := range cas {
		anchors = append(anchors, trust.Anchor{
			Cert:       ca.cert,
			Type:       typ,
			Country:    country,
			Status:     statusGranted,
			ValidUntil: ca.cert.NotAfter,
			TLSequence: 42,
		})
	}
	return &stubSource{
		anchors: map[string][]trust.Anchor{string(typ) + "|" + country: anchors},
		now:     t0,
	}
}

// ---- tests ----

// Happy path: leaf C=LV chains to an LV PID-provider anchor; provenance
// records the territory order verbatim.
func TestResolveHappyPathIssuingTerritory(t *testing.T) {
	ca := newTestCA(t, "LV PID IACA", "LV")
	leafDER, leafKey := ca.issueLeaf(t, "LV PID DS", "LV")
	src := sourceWith(trust.PIDProvider, "LV", ca)

	pub, ri, err := trust.ResolveIssuerKey(src, [][]byte{leafDER}, trust.PIDProvider)
	if err != nil {
		t.Fatalf("ResolveIssuerKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || !ecPub.Equal(&leafKey.PublicKey) {
		t.Fatalf("returned key is not the leaf public key (%T)", pub)
	}
	if ri.AnchorType != trust.PIDProvider {
		t.Errorf("AnchorType = %q", ri.AnchorType)
	}
	if ri.AnchorCountry != "LV" {
		t.Errorf("AnchorCountry = %q, want LV", ri.AnchorCountry)
	}
	if ri.AnchorFingerprint != fingerprintOf(ca.cert) {
		t.Errorf("AnchorFingerprint = %q, want %q", ri.AnchorFingerprint, fingerprintOf(ca.cert))
	}
	if ri.AnchorSubject != ca.cert.Subject.String() {
		t.Errorf("AnchorSubject = %q", ri.AnchorSubject)
	}
	if ri.Subject != "" && ri.Subject != mustLeafSubject(t, leafDER) {
		t.Errorf("Subject = %q", ri.Subject)
	}
	if got, want := fmt.Sprint(ri.TerritoriesTried), `[LV ]`; got != want {
		t.Errorf("TerritoriesTried = %v, want [LV \"\"]", ri.TerritoriesTried)
	}
	if got := fmt.Sprint(src.calls); got != `[pid_provider|LV]` {
		t.Errorf("source calls = %v, want only the issuing territory", src.calls)
	}
}

func mustLeafSubject(t *testing.T, der []byte) string {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c.Subject.String()
}

// Intermediates: leaf → sub-CA → root anchor.
func TestResolveWithIntermediate(t *testing.T) {
	root := newTestCA(t, "LV PID Root", "LV")
	sub := root.issueCA(t, "LV PID Sub CA", "LV")
	leafDER, _ := sub.issueLeaf(t, "LV PID DS 2", "LV")
	src := sourceWith(trust.PIDProvider, "LV", root)

	_, ri, err := trust.ResolveIssuerKey(src, [][]byte{leafDER, sub.cert.Raw}, trust.PIDProvider)
	if err != nil {
		t.Fatalf("ResolveIssuerKey with intermediate: %v", err)
	}
	if ri.AnchorFingerprint != fingerprintOf(root.cert) {
		t.Error("chain did not terminate at the root anchor")
	}
}

// Chain to the wrong anchor TYPE fails ([ARF §6.6.3.6]):
// the same CA registered as wallet_provider must not validate a PID chain.
func TestResolveWrongAnchorTypeFails(t *testing.T) {
	ca := newTestCA(t, "LV Wallet CA", "LV")
	leafDER, _ := ca.issueLeaf(t, "LV Wallet Unit", "LV")
	src := sourceWith(trust.WalletProvider, "LV", ca) // only wallet_provider

	_, _, err := trust.ResolveIssuerKey(src, [][]byte{leafDER}, trust.PIDProvider)
	if !errors.Is(err, trust.ErrChainUntrusted) {
		t.Fatalf("err = %v, want ErrChainUntrusted", err)
	}
}

// EU-level fallback: leaf C=DE, anchors only under country "" (EU-level
// list, anchor territory "EU") — resolution order DE then "" recorded.
func TestResolveEULevelFallback(t *testing.T) {
	ca := newTestCA(t, "EU Access CA", "EU")
	leafDER, _ := ca.issueLeaf(t, "DE Wallet RI", "DE")
	src := sourceWith(trust.AccessCA, "", ca)
	src.anchors[string(trust.AccessCA)+"|"] = []trust.Anchor{{
		Cert: ca.cert, Type: trust.AccessCA, Country: "EU",
		Status: statusGranted, ValidUntil: ca.cert.NotAfter, TLSequence: 7,
	}}

	_, ri, err := trust.ResolveIssuerKey(src, [][]byte{leafDER}, trust.AccessCA)
	if err != nil {
		t.Fatalf("ResolveIssuerKey: %v", err)
	}
	if got := fmt.Sprint(ri.TerritoriesTried); got != `[DE ]` {
		t.Errorf("TerritoriesTried = %v, want [DE \"\"]", ri.TerritoriesTried)
	}
	if ri.AnchorCountry != "EU" {
		t.Errorf("AnchorCountry = %q, want EU (verbatim from anchor)", ri.AnchorCountry)
	}
	if got := fmt.Sprint(src.calls); got != `[access_ca|DE access_ca|]` {
		t.Errorf("source calls = %v, want issuing territory then EU-level", src.calls)
	}
}

// Cross-country anchors are honored ONLY when country=""
// (acceptance): a DE leaf must not resolve against an anchor filed under LV.
func TestResolveCrossCountryNotHonored(t *testing.T) {
	ca := newTestCA(t, "LV PID IACA B", "LV")
	leafDER, _ := ca.issueLeaf(t, "DE PID DS", "DE")
	src := sourceWith(trust.PIDProvider, "LV", ca) // filed under LV only

	_, _, err := trust.ResolveIssuerKey(src, [][]byte{leafDER}, trust.PIDProvider)
	if !errors.Is(err, trust.ErrChainUntrusted) {
		t.Fatalf("err = %v, want ErrChainUntrusted", err)
	}
	if got := fmt.Sprint(src.calls); got != `[pid_provider|DE pid_provider|]` {
		t.Errorf("source calls = %v — the LV set must never be consulted", src.calls)
	}
}

// Degraded cache propagates immediately — a stale cache must not silently
// fall through to the EU-level query (fail closed).
func TestResolveCacheExpiredPropagates(t *testing.T) {
	ca := newTestCA(t, "LV PID IACA C", "LV")
	leafDER, _ := ca.issueLeaf(t, "LV PID DS 3", "LV")
	src := sourceWith(trust.PIDProvider, "LV", ca)
	src.err = trust.ErrCacheExpired

	_, _, err := trust.ResolveIssuerKey(src, [][]byte{leafDER}, trust.PIDProvider)
	if !errors.Is(err, trust.ErrCacheExpired) {
		t.Fatalf("err = %v, want ErrCacheExpired", err)
	}
	if len(src.calls) != 1 {
		t.Errorf("source calls = %v, want exactly 1 (no fall-through)", src.calls)
	}
}

// The injected clock (Now on the source) governs RFC 5280 time checks: at
// now beyond the anchor's NotAfter, the chain must fail.
func TestResolveClockFromSource(t *testing.T) {
	ca := newTestCA(t, "LV PID IACA D", "LV")
	leafDER, _ := ca.issueLeaf(t, "LV PID DS 4", "LV")
	src := sourceWith(trust.PIDProvider, "LV", ca)
	src.now = t0.Add(2 * 365 * 24 * time.Hour) // beyond CA NotAfter

	_, _, err := trust.ResolveIssuerKey(src, [][]byte{leafDER}, trust.PIDProvider)
	if !errors.Is(err, trust.ErrChainUntrusted) {
		t.Fatalf("err = %v, want ErrChainUntrusted (expired at injected now)", err)
	}
}

// Leaf without a country attribute goes straight to EU-level.
func TestResolveLeafWithoutCountry(t *testing.T) {
	ca := newTestCA(t, "No Country CA", "")
	leafDER, _ := ca.issueLeaf(t, "No Country DS", "")
	src := sourceWith(trust.PIDProvider, "", ca)

	_, ri, err := trust.ResolveIssuerKey(src, [][]byte{leafDER}, trust.PIDProvider)
	if err != nil {
		t.Fatalf("ResolveIssuerKey: %v", err)
	}
	if len(ri.TerritoriesTried) != 1 || ri.TerritoriesTried[0] != "" {
		t.Errorf("TerritoriesTried = %v, want [\"\"]", ri.TerritoriesTried)
	}
}

// Malformed input never panics and fails with ErrChainParse.
func TestResolveMalformedChain(t *testing.T) {
	src := &stubSource{anchors: map[string][]trust.Anchor{}, now: t0}
	tests := []struct {
		name  string
		chain [][]byte
	}{
		{"empty_chain", nil},
		{"garbage_leaf", [][]byte{{0xde, 0xad, 0xbe, 0xef}}},
		{"empty_cert", [][]byte{{}}},
		{"garbage_intermediate", [][]byte{validLeafDER(t), {0x00}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := trust.ResolveIssuerKey(src, tt.chain, trust.PIDProvider)
			if !errors.Is(err, trust.ErrChainParse) {
				t.Fatalf("err = %v, want ErrChainParse", err)
			}
		})
	}
}

func validLeafDER(t *testing.T) []byte {
	t.Helper()
	ca := newTestCA(t, "Filler CA", "LV")
	der, _ := ca.issueLeaf(t, "Filler DS", "LV")
	return der
}

func TestResolveUnknownType(t *testing.T) {
	src := &stubSource{anchors: map[string][]trust.Anchor{}, now: t0}
	_, _, err := trust.ResolveIssuerKey(src, [][]byte{validLeafDER(t)}, trust.AnchorType("bogus"))
	if !errors.Is(err, trust.ErrUnknownAnchorType) {
		t.Fatalf("err = %v, want ErrUnknownAnchorType", err)
	}
}

// FuzzResolveIssuerKey: the chain comes from the wallet (x5chain/x5c) —
// untrusted input, must not panic.
func FuzzResolveIssuerKey(f *testing.F) {
	ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9999),
		Subject:               pkix.Name{CommonName: "fuzz seed", Country: []string{"LV"}},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ca.PublicKey, ca)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(der)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01}) // tiny DER
	f.Add([]byte(""))
	src := &stubSource{anchors: map[string][]trust.Anchor{}, now: time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = trust.ResolveIssuerKey(src, [][]byte{data}, trust.PIDProvider)       // must not panic
		_, _, _ = trust.ResolveIssuerKey(src, [][]byte{data, data}, trust.PIDProvider) // with "intermediate"
	})
}
