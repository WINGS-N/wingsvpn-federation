package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/proxy"

	"wingsnet.org/federation/internal/agent/realitykeys"
	"wingsnet.org/federation/internal/agent/xrayproc"
)

// VerifyTimeout bounds one dest's real handshake test
const VerifyTimeout = 25 * time.Second

// Verifier completes real REALITY handshakes against a candidate.
//
// Everything but the dest handshake is loopback: a throwaway server, a throwaway
// client and a local HTTP endpoint the traffic is pulled from. Nothing leaves the
// machine except the TLS connection to the dest itself, which is the thing under
// test
type Verifier struct {
	XrayPath string
	WorkDir  string
	now      func() time.Time
}

// NewVerifier builds a verifier around an xray binary
func NewVerifier(xrayPath, workDir string) *Verifier {
	return &Verifier{XrayPath: xrayPath, WorkDir: workDir, now: time.Now}
}

// ErrNoBinary means there is no xray to test with, so no verdict is possible
var ErrNoBinary = errors.New("scan: no xray binary to verify with")

// Verify fills in RealityOK and PostQuantumOK.
//
// Both are tested, because they are different questions: a dest can carry plain
// REALITY and still be too small to hide the ML-DSA-65 signature
func (v *Verifier) Verify(ctx context.Context, res *Result) error {
	if v.XrayPath == "" {
		return ErrNoBinary
	}
	keys, err := realitykeys.Generate(v.XrayPath)
	if err != nil {
		return err
	}
	res.RealityOK = v.handshakeWorks(ctx, res.Host, res.Port, keys, false)
	if res.RealityOK {
		res.PostQuantumOK = keys.Mldsa65Seed != "" &&
			v.handshakeWorks(ctx, res.Host, res.Port, keys, true)
	}
	return nil
}

// handshakeWorks stands a server and a client up against the candidate and pulls
// one byte through. Anything less is not evidence: a handshake can complete and
// still carry nothing
func (v *Verifier) handshakeWorks(ctx context.Context, host string, port int, keys realitykeys.Pair, postQuantum bool) bool {
	ctx, cancel := context.WithTimeout(ctx, VerifyTimeout)
	defer cancel()

	echo, echoAddr, err := startEcho()
	if err != nil {
		return false
	}
	defer func() { _ = echo.Close() }()

	inbound, err := freePort()
	if err != nil {
		return false
	}
	socks, err := freePort()
	if err != nil {
		return false
	}

	dir := filepath.Join(v.WorkDir, fmt.Sprintf("verify-%d", inbound))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	defer func() { _ = os.RemoveAll(dir) }()

	const uuid = "00000000-0000-4000-8000-000000000001"
	serverCfg, err := verifyServerConfig(host, port, inbound, uuid, keys, postQuantum)
	if err != nil {
		return false
	}
	clientCfg, err := verifyClientConfig(host, inbound, socks, uuid, keys, postQuantum)
	if err != nil {
		return false
	}
	serverPath := filepath.Join(dir, "server.json")
	clientPath := filepath.Join(dir, "client.json")
	if os.WriteFile(serverPath, serverCfg, 0o600) != nil || os.WriteFile(clientPath, clientCfg, 0o600) != nil {
		return false
	}

	server := xrayproc.New(v.XrayPath, serverPath)
	if server.Start() != nil {
		return false
	}
	defer func() { _ = server.Stop() }()
	if waitForPort(ctx, inbound) != nil {
		return false
	}

	client := xrayproc.New(v.XrayPath, clientPath)
	if client.Start() != nil {
		return false
	}
	defer func() { _ = client.Stop() }()
	if waitForPort(ctx, socks) != nil {
		return false
	}

	return pullThrough(ctx, socks, echoAddr)
}

// startEcho serves a single byte on loopback, so the test needs no internet
// beyond the dest handshake
func startEcho() (net.Listener, string, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	go func() {
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("k"))
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		_ = srv.Serve(lis)
	}()
	return lis, lis.Addr().String(), nil
}

func pullThrough(ctx context.Context, socksPort int, target string) bool {
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", itoa(socksPort)), nil, proxy.Direct)
	if err != nil {
		return false
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if cd, ok := dialer.(proxy.ContextDialer); ok {
					return cd.DialContext(ctx, network, addr)
				}
				return dialer.Dial(network, addr)
			},
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return err == nil && len(body) > 0
}

func freePort() (int, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = lis.Close() }()
	return lis.Addr().(*net.TCPAddr).Port, nil
}

func waitForPort(ctx context.Context, port int) error {
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("scan: xray never started listening")
}

func verifyServerConfig(host string, port, inbound int, uuid string, keys realitykeys.Pair, postQuantum bool) ([]byte, error) {
	reality := map[string]any{
		"dest":        net.JoinHostPort(host, itoa(port)),
		"serverNames": []string{host},
		"privateKey":  keys.PrivateKey,
		"shortIds":    []string{shortID},
	}
	if postQuantum {
		reality["mldsa65Seed"] = keys.Mldsa65Seed
	}
	return json.MarshalIndent(map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []map[string]any{{
			"listen":   "127.0.0.1",
			"port":     inbound,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []map[string]any{{"id": uuid}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality", "realitySettings": reality,
			},
		}},
		"outbounds": []map[string]any{{"protocol": "freedom"}},
	}, "", "  ")
}

func verifyClientConfig(host string, inbound, socks int, uuid string, keys realitykeys.Pair, postQuantum bool) ([]byte, error) {
	reality := map[string]any{
		"serverName":  host,
		"publicKey":   keys.PublicKey,
		"shortId":     shortID,
		"fingerprint": "chrome",
	}
	if postQuantum {
		reality["mldsa65Verify"] = keys.Mldsa65Verify
	}
	return json.MarshalIndent(map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []map[string]any{{
			"listen": "127.0.0.1", "port": socks, "protocol": "socks",
			"settings": map[string]any{"udp": false},
		}},
		"outbounds": []map[string]any{{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []map[string]any{{
				"address": "127.0.0.1", "port": inbound,
				"users": []map[string]any{{"id": uuid, "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality", "realitySettings": reality,
			},
		}},
	}, "", "  ")
}

// shortID is fixed for the test: it is thrown away with the keys
const shortID = "0123456789abcdef"

func itoa(v int) string { return fmt.Sprintf("%d", v) }
