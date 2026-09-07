package vktpctl

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	controlpb "wingsnet.org/federation/gen/controlpb"
)

type fakeRelay struct {
	controlpb.UnimplementedRelayServer
	status *controlpb.Status
	flows  *controlpb.FlowStats
	fail   bool
}

func (f *fakeRelay) GetStatus(context.Context, *controlpb.GetStatusRequest) (*controlpb.Status, error) {
	if f.fail {
		return nil, context.DeadlineExceeded
	}
	return f.status, nil
}

func (f *fakeRelay) GetFlowStats(context.Context, *controlpb.GetFlowStatsRequest) (*controlpb.FlowStats, error) {
	if f.fail {
		return nil, context.DeadlineExceeded
	}
	return f.flows, nil
}

func dialFake(t *testing.T, relay *fakeRelay) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	controlpb.RegisterRelayServer(gs, relay)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecureCreds{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &Client{conn: conn, relay: controlpb.NewRelayClient(conn)}
}

func TestStatusReadsTheRelay(t *testing.T) {
	c := dialFake(t, &fakeRelay{status: &controlpb.Status{
		Version:        "v2.1.0",
		Ready:          true,
		BootId:         "boot-1",
		PeerCount:      3,
		ActiveSessions: 7,
		ListenEndpoint: "0.0.0.0:56000",
		AesNi:          true,
		WrapCipher:     "srtp-aes-gcm",
		UptimeSeconds:  120,
	}})
	st := c.Status(context.Background())
	if !st.Reachable || !st.Ready {
		t.Fatalf("state = %+v, want reachable and ready", st)
	}
	if st.Version != "v2.1.0" || st.BootID != "boot-1" || st.PeerCount != 3 {
		t.Errorf("state = %+v", st)
	}
	if st.Uptime != 2*time.Minute {
		t.Errorf("uptime = %s, want 2m", st.Uptime)
	}
}

// A relay that is starting up or wedged must come back as not ready rather than
// as an error the supervisor has to interpret; both are ordinary states
func TestUnreachableRelayIsNotReady(t *testing.T) {
	c := dialFake(t, &fakeRelay{fail: true})
	st := c.Status(context.Background())
	if st.Reachable {
		t.Error("an unreachable relay reported itself reachable")
	}
	if st.Ready {
		t.Error("an unreachable relay reported itself ready")
	}
}

// Running is not the same as serving: the supervisor must not mark a node
// healthy while the relay cannot carry traffic yet
func TestRunningButNotServingIsNotReady(t *testing.T) {
	c := dialFake(t, &fakeRelay{status: &controlpb.Status{Version: "v2.1.0", Ready: false}})
	st := c.Status(context.Background())
	if !st.Reachable {
		t.Error("a relay that answered was marked unreachable")
	}
	if st.Ready {
		t.Error("a relay that answered but is not serving was marked ready")
	}
}

func TestFlowStatsMapsCounters(t *testing.T) {
	c := dialFake(t, &fakeRelay{flows: &controlpb.FlowStats{
		ActiveStreams: 4, ActiveSessions: 2, ServerRxBytes: 1000, ServerTxBytes: 2000,
	}})
	flow, err := c.FlowStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if flow.RxBytes != 1000 || flow.TxBytes != 2000 || flow.ActiveStreams != 4 {
		t.Errorf("flow = %+v", flow)
	}
	failing := dialFake(t, &fakeRelay{fail: true})
	if _, err := failing.FlowStats(context.Background()); err != ErrNotReachable {
		t.Errorf("err = %v, want ErrNotReachable", err)
	}
}
