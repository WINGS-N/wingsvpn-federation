package probe

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
	"wingsnet.org/federation/internal/dialpick"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

func target(transport string) *fedpb.ProbeTarget {
	return &fedpb.ProbeTarget{
		NodeId: "n1", Transport: transport, Host: "203.0.113.7", Port: 443,
		Uuid: "uuid-1", Flow: "xtls-rprx-vision",
		RealityPublicKey: "PBK", Mldsa65Verify: "PQV",
		ServerName: "www.example.com", ShortId: "abcd", XhttpPath: "/dl",
		DownloadUrl: "https://example.invalid/down",
	}
}

// The measurement has to run over the same path a user takes, or it measures
// something else entirely
func TestClientConfigDialsTheTargetOverReality(t *testing.T) {
	raw, err := clientConfig(target("tcp"), 41080)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := doc["outbounds"].([]any)[0].(map[string]any)
	vnext := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if vnext["address"] != "203.0.113.7" || vnext["port"].(float64) != 443 {
		t.Errorf("outbound = %v", vnext)
	}
	user := vnext["users"].([]any)[0].(map[string]any)
	if user["id"] != "uuid-1" || user["flow"] != "xtls-rprx-vision" {
		t.Errorf("user = %v", user)
	}
	stream := out["streamSettings"].(map[string]any)
	if stream["security"] != "reality" || stream["network"] != "tcp" {
		t.Errorf("stream = %v", stream)
	}
	reality := stream["realitySettings"].(map[string]any)
	if reality["publicKey"] != "PBK" || reality["shortId"] != "abcd" || reality["serverName"] != "www.example.com" {
		t.Errorf("reality = %v", reality)
	}
	// A node configured with post-quantum verification refuses a client that
	// omits it, and that failure would be blamed on the node
	if reality["mldsa65Verify"] != "PQV" {
		t.Errorf("reality lacks the post-quantum verify half: %v", reality)
	}
	in := doc["inbounds"].([]any)[0].(map[string]any)
	if in["protocol"] != "socks" || in["listen"] != "127.0.0.1" {
		t.Errorf("inbound = %v", in)
	}
}

// A vision account refuses a client sending an empty flow, and the xhttp inbound
// refuses one sending vision, so the transport decides the shape
func TestXhttpConfigCarriesItsPathAndNoFlow(t *testing.T) {
	xt := target("xhttp")
	xt.Flow = ""
	raw, err := clientConfig(xt, 41080)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	stream := doc["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	if stream["network"] != "xhttp" {
		t.Fatalf("network = %v", stream["network"])
	}
	if got := stream["xhttpSettings"].(map[string]any)["path"]; got != "/dl" {
		t.Errorf("path = %v", got)
	}
}

// A vantage point with no Xray reports that it could not measure, rather than
// reporting the node as broken
func TestMeasurerWithoutABinaryBlamesItself(t *testing.T) {
	m := NewMeasurer("", t.TempDir(), 41080)
	report := m.Measure(context.Background(), target("tcp"))
	if report.GetHandshakeOk() {
		t.Error("claimed a successful measurement with no binary")
	}
	if report.GetError() == "" {
		t.Error("no reason given")
	}
	if report.GetNodeId() != "n1" || report.GetAddress() != "203.0.113.7" {
		t.Errorf("report does not say what it was measuring: %+v", report)
	}
}

type fakeHead struct {
	fedpb.UnimplementedFederationServer
	task    *fedpb.ProbeTask
	reports chan *fedpb.ProbeReport
	hello   chan *fedpb.ProbeHello
}

func (f *fakeHead) ProbeSession(stream fedpb.Federation_ProbeSessionServer) error {
	for {
		frame, err := stream.Recv()
		if err != nil {
			return nil
		}
		switch payload := frame.GetFrame().(type) {
		case *fedpb.ProbeFrame_Hello:
			f.hello <- payload.Hello
			if err := stream.Send(f.task); err != nil {
				return err
			}
		case *fedpb.ProbeFrame_Report:
			f.reports <- payload.Report
		}
	}
}

// The whole point of the role: targets come down, measurements go back up
func TestProbeMeasuresWhatItIsGivenAndReportsBack(t *testing.T) {
	head := &fakeHead{
		task: &fedpb.ProbeTask{
			IntervalSeconds: 3600,
			Targets:         []*fedpb.ProbeTarget{target("tcp"), target("xhttp")},
		},
		reports: make(chan *fedpb.ProbeReport, 8),
		hello:   make(chan *fedpb.ProbeHello, 1),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	fedpb.RegisterFederationServer(gs, head)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	measured := make(chan string, 8)
	cfg := Config{
		HeadEndpoint: lis.Addr().String(),
		ProbeID:      "probe-ru",
		Region:       "RU",
		Dial: func(_ context.Context, endpoint string) (*grpc.ClientConn, error) {
			return grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
		},
		Measure: func(_ context.Context, target *fedpb.ProbeTarget) *fedpb.ProbeReport {
			measured <- target.GetTransport()
			return &fedpb.ProbeReport{
				NodeId: target.GetNodeId(), Address: target.GetHost(),
				Transport: target.GetTransport(), HandshakeOk: true,
				DownloadBps: 8_000_000, RttMs: 42,
			}
		},
	}
	go func() { _ = runOnce(ctx, cfg, dialpick.New(cfg.HeadEndpoint)) }()

	select {
	case hello := <-head.hello:
		if hello.GetProbeId() != "probe-ru" || hello.GetRegion() != "RU" {
			t.Errorf("hello = %+v", hello)
		}
	case <-ctx.Done():
		t.Fatal("no hello arrived")
	}

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case report := <-head.reports:
			seen[report.GetTransport()] = true
			if !report.GetHandshakeOk() || report.GetDownloadBps() == 0 {
				t.Errorf("report = %+v", report)
			}
		case <-ctx.Done():
			t.Fatalf("only %d reports arrived", len(seen))
		}
	}
	if !seen["tcp"] || !seen["xhttp"] {
		t.Errorf("transports measured = %v, want both", seen)
	}
}

// Two measurements at once compete for the vantage point's own uplink and both
// come out looking shaped
func TestTargetsAreMeasuredOneAtATime(t *testing.T) {
	var concurrent, peak int
	done := make(chan struct{})
	cfg := Config{
		Measure: func(_ context.Context, target *fedpb.ProbeTarget) *fedpb.ProbeReport {
			concurrent++
			if concurrent > peak {
				peak = concurrent
			}
			time.Sleep(time.Millisecond)
			concurrent--
			return &fedpb.ProbeReport{NodeId: target.GetNodeId()}
		},
	}
	ready := make(chan *fedpb.ProbeReport, 8)
	go func() {
		measureAll(context.Background(), cfg, &fedpb.ProbeTask{
			Targets: []*fedpb.ProbeTarget{target("tcp"), target("xhttp"), target("tcp")},
		}, ready)
		close(done)
	}()
	<-done
	if peak != 1 {
		t.Errorf("peak concurrency = %d, want 1", peak)
	}
}

// Голый IPv6 отличается от имени и от IPv4: точке наблюдения без IPv6 мерить
// его нечем, и её отчёт сказал бы про её собственную сеть
func TestIsIPv6(t *testing.T) {
	for _, addr := range []string{"[2a0e:97c0:3ea:1f4::1]:443", "2a0e:97c0:3ea:1f4::1"} {
		if !isIPv6(addr) {
			t.Errorf("%s не опознан как IPv6", addr)
		}
	}
	for _, addr := range []string{"37.187.140.126:443", "node.example.org:443", "10.0.0.1"} {
		if isIPv6(addr) {
			t.Errorf("%s ошибочно принят за IPv6", addr)
		}
	}
}
