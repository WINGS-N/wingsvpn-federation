// Package scan decides which hosts a node may borrow a TLS identity from.
//
// The cheap half is a TLS probe, ported in shape from the 3x-ui fork's
// reality_scan.go: negotiate TLS 1.3 with h2 and X25519, check the certificate,
// and harvest its SANs. The expensive half is Verify, which completes an actual
// REALITY handshake, because nothing observable at the TLS layer predicts
// whether REALITY will work - let alone whether the ML-DSA-65 signature fits
package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds one TLS probe
const DefaultTimeout = 8 * time.Second

// Result is what is known about one candidate
type Result struct {
	Target string
	Host   string
	Port   int

	// Feasible is the TLS-level verdict: worth spending a real handshake on
	Feasible   bool
	TLS13      bool
	H2         bool
	X25519     bool
	CertValid  bool
	CertIssuer string
	NotAfter   time.Time
	// ServerNames are the certificate's SANs, each a usable SNI in its own
	// right. This is how one host yields a pool: the cert on music.yandex.ru
	// also covers the .uz and .kz names
	ServerNames []string
	// HandshakeBytes is what the host sent back. Kept for diagnosis: it
	// correlates with whether ML-DSA-65 fits but does not decide it
	HandshakeBytes int
	LatencyMs      int

	// RealityOK and PostQuantumOK are set by Verify and are the only trustworthy
	// answers here
	RealityOK     bool
	PostQuantumOK bool

	Error string
}

// counting counts the bytes a peer sent during the handshake
type counting struct {
	net.Conn
	read int
}

func (c *counting) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read += n
	return n, err
}

// Probe runs the cheap TLS check against one host
func Probe(ctx context.Context, host string, port int, timeout time.Duration) *Result {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if port == 0 {
		port = 443
	}
	res := &Result{Host: host, Port: port, Target: net.JoinHostPort(host, strconv.Itoa(port))}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", res.Target)
	if err != nil {
		res.Error = "connection failed: " + err.Error()
		return res
	}
	counted := &counting{Conn: raw}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	conn := tls.Client(counted, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		// The order matters: a host that only offers plain X25519 still works,
		// but one that forces a hello retry is trouble for REALITY
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		res.Error = "tls handshake failed: " + err.Error()
		return res
	}
	res.LatencyMs = int(time.Since(started).Milliseconds())
	res.HandshakeBytes = counted.read

	st := conn.ConnectionState()
	res.TLS13 = st.Version == tls.VersionTLS13
	res.H2 = st.NegotiatedProtocol == "h2"
	res.X25519 = st.CurveID == tls.X25519 || st.CurveID == tls.X25519MLKEM768

	if len(st.PeerCertificates) == 0 {
		res.Error = "no certificate presented"
		return res
	}
	leaf := st.PeerCertificates[0]
	res.ServerNames = usableSANs(leaf.DNSNames)
	res.NotAfter = leaf.NotAfter
	if len(leaf.Issuer.Organization) > 0 {
		res.CertIssuer = leaf.Issuer.Organization[0]
	} else {
		res.CertIssuer = leaf.Issuer.CommonName
	}
	opts := x509.VerifyOptions{DNSName: host, Intermediates: x509.NewCertPool()}
	for _, c := range st.PeerCertificates[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(opts); err != nil {
		res.Error = "certificate not trusted: " + err.Error()
	} else {
		res.CertValid = true
	}

	// h2 is a preference, not a requirement. 3x-ui's scanner insists on it as a
	// quality heuristic, but REALITY does not care: 360.yandex.ru,
	// sso.passport.yandex.ru and smartcaptcha.yandexcloud.net all refuse h2 and
	// all carry REALITY, and all three are in production use. Requiring it culled
	// working dests
	res.Feasible = res.TLS13 && res.X25519 && res.CertValid
	if !res.Feasible && res.Error == "" {
		switch {
		case !res.TLS13:
			res.Error = "no tls 1.3"
		case !res.X25519:
			res.Error = "no x25519 key exchange"
		}
	}
	return res
}

// usableSANs drops wildcards: a wildcard is not a name a client can send
func usableSANs(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || strings.HasPrefix(n, "*.") {
			continue
		}
		out = append(out, n)
	}
	return out
}

// ProbeAll runs the cheap check over a list, bounded by concurrency
func ProbeAll(ctx context.Context, targets []string, concurrency int, timeout time.Duration) []*Result {
	if concurrency <= 0 {
		concurrency = 8
	}
	out := make([]*Result, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			host, port := splitTarget(target)
			out[i] = Probe(ctx, host, port, timeout)
		}(i, target)
	}
	wg.Wait()
	return out
}

func splitTarget(target string) (string, int) {
	target = strings.TrimSpace(target)
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, 443
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 443
	}
	return host, port
}
