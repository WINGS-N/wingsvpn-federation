package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A wildcard is not a name a client can send, so it is not a usable dest
func TestWildcardSANsAreDropped(t *testing.T) {
	got := usableSANs([]string{"*.yandex.ru", "music.yandex.ru", "  ", "music.yandex.uz"})
	if len(got) != 2 || got[0] != "music.yandex.ru" || got[1] != "music.yandex.uz" {
		t.Errorf("usable = %v", got)
	}
}

// Most of the value of scanning: one certificate names a dozen usable dests, and
// each looks like an entirely different destination to anyone watching
func TestExpandSANsGrowsThePoolFromCertificates(t *testing.T) {
	got := ExpandSANs([]*Result{
		{Feasible: true, ServerNames: []string{"music.yandex.ru", "music.yandex.uz", "music.yandex.kz"}},
		{Feasible: true, ServerNames: []string{"music.yandex.ru", "music.ya.ru"}},
		{Feasible: false, ServerNames: []string{"never.example"}},
	})
	if len(got) != 4 {
		t.Fatalf("expanded to %v, want four distinct names", got)
	}
	for _, name := range got {
		if name == "never.example" {
			t.Error("a name from an unusable host got into the pool")
		}
	}
}

// Post-quantum outranks latency: it is a property the whole fleet either has or
// does not, while tens of milliseconds on the borrowed handshake cost nothing
func TestBestPrefersAVerifiedPostQuantumDest(t *testing.T) {
	fast := &Result{Host: "fast", Target: "fast:443", RealityOK: true, LatencyMs: 20}
	pq := &Result{Host: "pq", Target: "pq:443", RealityOK: true, PostQuantumOK: true, LatencyMs: 200}
	broken := &Result{Host: "broken", Target: "broken:443", PostQuantumOK: true}
	if got := Best([]*Result{fast, pq, broken}); got != pq {
		t.Errorf("best = %v, want the post-quantum one", got)
	}
	// And a dest that failed the real handshake never wins, whatever it claims
	if got := Best([]*Result{broken}); got != nil {
		t.Errorf("best = %v, want nothing usable", got)
	}
}

func TestBestBreaksTiesOnLatency(t *testing.T) {
	slow := &Result{Host: "slow", RealityOK: true, PostQuantumOK: true, LatencyMs: 300}
	quick := &Result{Host: "quick", RealityOK: true, PostQuantumOK: true, LatencyMs: 40}
	if got := Best([]*Result{slow, quick}); got != quick {
		t.Errorf("best = %v, want the quicker one", got)
	}
}

func TestSplitTargetDefaultsToTheTLSPort(t *testing.T) {
	for _, tc := range []struct {
		in   string
		host string
		port int
	}{
		{"music.yandex.ru:443", "music.yandex.ru", 443},
		{"music.yandex.ru", "music.yandex.ru", 443},
		{" dl.google.com:8443 ", "dl.google.com", 8443},
	} {
		host, port := splitTarget(tc.in)
		if host != tc.host || port != tc.port {
			t.Errorf("splitTarget(%q) = %q/%d", tc.in, host, port)
		}
	}
}

// startTLS stands up a local TLS 1.3 server so the probe can be tested without
// reaching the internet
func startTLS(t *testing.T, alpn []string) (string, int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost", "*.wild.example", "second.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   alpn,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				time.Sleep(50 * time.Millisecond)
				_ = conn.Close()
			}()
		}
	}()
	t.Cleanup(func() { _ = lis.Close() })
	addr := lis.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestProbeReportsWhatItSaw(t *testing.T) {
	host, port := startTLS(t, []string{"h2"})
	res := Probe(context.Background(), host, port, 5*time.Second)
	if !res.TLS13 || !res.H2 || !res.X25519 {
		t.Errorf("result = %+v, want tls13 + h2 + x25519", res)
	}
	if res.HandshakeBytes == 0 {
		t.Error("handshake bytes not counted")
	}
	// The self-signed certificate is not trusted, so this must not be feasible
	if res.Feasible || res.CertValid {
		t.Errorf("an untrusted certificate was accepted: %+v", res)
	}
	if len(res.ServerNames) != 2 {
		t.Errorf("server names = %v, want the wildcard dropped", res.ServerNames)
	}
	if res.Target != net.JoinHostPort(host, strconv.Itoa(port)) {
		t.Errorf("target = %q", res.Target)
	}
}

// h2 is a preference, not a requirement: three Yandex hosts in production use
// refuse it and carry REALITY perfectly well, so culling on it threw away
// working dests
func TestAHostWithoutH2IsStillACandidate(t *testing.T) {
	host, port := startTLS(t, []string{"http/1.1"})
	res := Probe(context.Background(), host, port, 5*time.Second)
	if res.H2 {
		t.Error("h2 reported where none was negotiated")
	}
	if res.Error != "certificate not trusted: x509: certificate signed by unknown authority" &&
		!strings.Contains(res.Error, "certificate") {
		t.Errorf("error = %q, want the certificate to be the only complaint", res.Error)
	}
}

// Among dests that work, one speaking h2 is a more convincing thing to imitate
func TestBestPrefersH2AmongEquals(t *testing.T) {
	plain := &Result{Host: "plain", RealityOK: true, PostQuantumOK: true, LatencyMs: 50}
	withH2 := &Result{Host: "h2", RealityOK: true, PostQuantumOK: true, H2: true, LatencyMs: 50}
	if got := Best([]*Result{plain, withH2}); got != withH2 {
		t.Errorf("best = %v, want the h2 one", got)
	}
}

func TestProbeReportsAnUnreachableHost(t *testing.T) {
	res := Probe(context.Background(), "127.0.0.1", 1, time.Second)
	if res.Feasible || res.Error == "" {
		t.Errorf("result = %+v", res)
	}
}

// A verifier with no binary must say it cannot verify, rather than report the
// dest as broken
func TestVerifyWithoutABinaryIsNotAVerdict(t *testing.T) {
	v := NewVerifier("", t.TempDir())
	res := &Result{Host: "example.com", Port: 443, Feasible: true}
	if err := v.Verify(context.Background(), res); err == nil {
		t.Fatal("claimed a verdict with no binary")
	}
	if res.RealityOK || res.PostQuantumOK {
		t.Errorf("result = %+v, want nothing claimed", res)
	}
}

func TestPoolsAreDistinctAndNonEmpty(t *testing.T) {
	if len(RussianPool) == 0 || len(GlobalPool) == 0 {
		t.Fatal("a pool is empty")
	}
	seen := map[string]bool{}
	for _, target := range DefaultPool() {
		if seen[target] {
			t.Errorf("%s appears twice in the default pool", target)
		}
		seen[target] = true
	}
	if len(DefaultPool()) != len(RussianPool)+len(GlobalPool) {
		t.Error("the default pool is not both pools")
	}
}
