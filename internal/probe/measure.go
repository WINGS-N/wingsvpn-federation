package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/agent/xrayproc"
)

// startTimeout bounds how long a local Xray gets to accept a connection before
// the target is called unreachable. Generous: a slow vantage point is not a
// broken node
const startTimeout = 10 * time.Second

// transferTimeout bounds one measurement. A node that cannot deliver the sample
// inside it is shaped hard enough that the exact number stops mattering
const transferTimeout = 30 * time.Second

// Measurer runs one target at a time through a local Xray
type Measurer struct {
	// XrayPath is the binary the vantage point measures with
	XrayPath string
	// WorkDir holds the rendered client config
	WorkDir string
	// SocksPort is where the local Xray offers the tunnel
	SocksPort int
	now       func() time.Time
}

// NewMeasurer builds a measurer
func NewMeasurer(xrayPath, workDir string, socksPort int) *Measurer {
	return &Measurer{XrayPath: xrayPath, WorkDir: workDir, SocksPort: socksPort, now: time.Now}
}

// ErrNoBinary means the vantage point has no Xray to measure with
var ErrNoBinary = errors.New("probe: no xray binary")

// Measure pulls bytes through one target and reports what happened.
//
// A failure is a result, not an error: "this node is unreachable from here" is
// exactly what the head needs to know, and swallowing it would leave a shaped
// node looking untested rather than bad
func (m *Measurer) Measure(ctx context.Context, target *fedpb.ProbeTarget) *fedpb.ProbeReport {
	report := &fedpb.ProbeReport{
		NodeId:       target.GetNodeId(),
		Address:      target.GetHost(),
		Transport:    transportOf(target),
		MeasuredUnix: m.now().Unix(),
	}
	if m.XrayPath == "" {
		report.Error = ErrNoBinary.Error()
		return report
	}

	configPath := filepath.Join(m.WorkDir, "probe.json")
	rendered, err := clientConfig(target, m.SocksPort)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	if err := os.MkdirAll(m.WorkDir, 0o700); err != nil {
		report.Error = err.Error()
		return report
	}
	if err := os.WriteFile(configPath, rendered, 0o600); err != nil {
		report.Error = err.Error()
		return report
	}

	// Прошлый замер поднимал свой Xray на этом же порту. Пока он не отпустит
	// сокет, новый его не займёт, а waitForPort увидит умирающего предшественника
	// и скажет "готово" - дальше запрос упирается в RST
	if err := waitForPortFree(ctx, m.SocksPort, startTimeout); err != nil {
		report.Error = err.Error()
		return report
	}

	proc := xrayproc.New(m.XrayPath, configPath)
	if err := proc.Start(); err != nil {
		report.Error = err.Error()
		return report
	}
	defer func() { _ = proc.Stop() }()

	if err := waitForPort(ctx, m.SocksPort, startTimeout); err != nil {
		report.Error = err.Error()
		return report
	}

	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", itoa(m.SocksPort)), nil, proxy.Direct)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
					return contextDialer.DialContext(ctx, network, addr)
				}
				return dialer.Dial(network, addr)
			},
			DisableKeepAlives: true,
		},
		Timeout: transferTimeout,
	}

	fetchCtx, cancel := context.WithTimeout(ctx, transferTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, target.GetDownloadUrl(), nil)
	if err != nil {
		report.Error = err.Error()
		return report
	}

	started := m.now()
	resp, err := client.Do(req)
	if err != nil && isTransient(err) {
		// Порт уже слушает, но SOCKS ещё не разобрался с сессией: одна повторная
		// попытка стоит дешевле, чем ложная отметка "нода недостижима"
		time.Sleep(retryDelay)
		started = m.now()
		retry, retryErr := http.NewRequestWithContext(fetchCtx, http.MethodGet, target.GetDownloadUrl(), nil)
		if retryErr == nil {
			resp, err = client.Do(retry)
		}
	}
	if err != nil {
		report.Error = err.Error()
		return report
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	// Time to the response header is the round trip through the tunnel: the
	// handshake plus one exchange with the far end
	firstByte := m.now()
	report.HandshakeMs = uint32(firstByte.Sub(started).Milliseconds())
	report.RttMs = report.HandshakeMs

	read, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	elapsed := m.now().Sub(firstByte).Seconds()
	if elapsed > 0 {
		report.DownloadBps = uint64(float64(read) / elapsed)
	}
	report.HandshakeOk = read > 0
	if read == 0 {
		report.Error = "the tunnel delivered no bytes"
	}
	return report
}

// waitForPort waits for the local Xray to start listening. Polling beats a fixed
// sleep: a slow vantage point would otherwise report every node as unreachable
// retryDelay - пауза перед единственной повторной попыткой
const retryDelay = 700 * time.Millisecond

// isTransient отличает "ещё не поднялся" от настоящего отказа ноды. Обрыв на
// локальном конце туннеля про ноду не говорит ничего
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, io.EOF) {
		return true
	}
	text := err.Error()
	return strings.Contains(text, "connection reset by peer") ||
		strings.Contains(text, "connection refused") ||
		strings.Contains(text, "EOF")
}

// waitForPortFree ждёт, пока порт перестанет отвечать: значит предыдущий Xray
// его отпустил
func waitForPortFree(ctx context.Context, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return nil
		}
		_ = conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("probe: the previous local xray never let go of the port")
}

func waitForPort(ctx context.Context, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
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
	return errors.New("probe: local xray never started listening")
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
