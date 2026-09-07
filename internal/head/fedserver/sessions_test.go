package fedserver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
	"wingsnet.org/federation/internal/head/tokens"
)

func serveFed(t *testing.T) (*Server, fedpb.FederationClient) {
	t.Helper()
	reg := registry.New()
	srv := New(reg, tokens.New(), "127.0.0.1:0")
	reg.Add(&registry.Node{ID: "node-1", Secret: "sekrit", DonorID: "d1"})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	fedpb.RegisterFederationServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
	})
	return srv, fedpb.NewFederationClient(conn)
}

func openSession(t *testing.T, client fedpb.FederationClient) fedpb.Federation_SessionClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	ctx = metadata.AppendToOutgoingContext(ctx, "wingsv-node-id", "node-1", "wingsv-node-secret", "sekrit")
	stream, err := client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&fedpb.AgentFrame{Frame: &fedpb.AgentFrame_Hello{
		Hello: &fedpb.Hello{NodeId: "node-1", BootId: "b1"},
	}}); err != nil {
		t.Fatal(err)
	}
	return stream
}

func waitConnected(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.Connected()) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the session never registered")
}

// Adding a user has to reach a node that is not saying anything right now. Until
// this existed the head could only answer, never command
func TestProfilesReachAnIdleNode(t *testing.T) {
	srv, client := serveFed(t)
	stream := openSession(t, client)
	waitConnected(t, srv)

	err := srv.PushProfiles("node-1", []*fedpb.ProfileSpec{
		{ProfileId: "p1", Uuid: "u1", Email: "f-deadbeef", InboundTag: "fed-tcp", Flow: "xtls-rprx-vision", Metered: true},
		{ProfileId: "p1", Uuid: "u1", Email: "f-deadbeef", InboundTag: "fed-xhttp", Metered: true},
	}, []string{"p0"})
	if err != nil {
		t.Fatal(err)
	}

	frame, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	delta := frame.GetProfileDelta()
	if delta == nil {
		t.Fatalf("got %T, want a profile delta", frame.GetFrame())
	}
	if len(delta.GetAdd()) != 2 || delta.GetAdd()[0].GetFlow() != "xtls-rprx-vision" || delta.GetAdd()[1].GetFlow() != "" {
		t.Errorf("delta add = %+v", delta.GetAdd())
	}
	if len(delta.GetRemoveProfileIds()) != 1 {
		t.Errorf("delta remove = %v", delta.GetRemoveProfileIds())
	}
}

func TestRotationReachesANode(t *testing.T) {
	srv, client := serveFed(t)
	stream := openSession(t, client)
	waitConnected(t, srv)

	if err := srv.PushRotation("node-1", fedpb.RotationState_ROTATION_STATE_DRAINING, "budget"); err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if got := frame.GetRotation(); got.GetState() != fedpb.RotationState_ROTATION_STATE_DRAINING || got.GetReason() != "budget" {
		t.Errorf("rotation = %+v", got)
	}
}

// A node that is simply not connected is a normal state, not an error to shout
// about - but it must not look like the command was delivered
func TestPushToAnAbsentNodeSaysSo(t *testing.T) {
	srv, _ := serveFed(t)
	err := srv.PushRotation("node-1", fedpb.RotationState_ROTATION_STATE_PARKED, "gone")
	if !errors.Is(err, ErrNotConnected) {
		t.Errorf("err = %v, want ErrNotConnected", err)
	}
}

// Commands are not stats: a backlog must be reported, because a node that missed
// a profile removal is still serving somebody who was cut off
func TestABackloggedNodeIsReportedRatherThanSilentlyDropped(t *testing.T) {
	sess := newSession()
	for i := 0; i < outboundDepth; i++ {
		if err := sess.send(&fedpb.HeadFrame{}); err != nil {
			t.Fatalf("queueing %d: %v", i, err)
		}
	}
	if err := sess.send(&fedpb.HeadFrame{}); !errors.Is(err, ErrBacklogged) {
		t.Errorf("err = %v, want ErrBacklogged", err)
	}
	sess.close()
	if err := sess.send(&fedpb.HeadFrame{}); !errors.Is(err, ErrNotConnected) {
		t.Errorf("err = %v after close, want ErrNotConnected", err)
	}
}

// A node that reconnects before the head noticed the old stream died must not
// leave a stale session that swallows its commands
func TestAReconnectReplacesTheOldSession(t *testing.T) {
	srv, _ := serveFed(t)
	first := srv.register("node-1")
	second := srv.register("node-1")
	if err := first.send(&fedpb.HeadFrame{}); !errors.Is(err, ErrNotConnected) {
		t.Errorf("the stale session still accepted a command: %v", err)
	}
	if err := second.send(&fedpb.HeadFrame{}); err != nil {
		t.Errorf("the live session refused a command: %v", err)
	}
	if got := srv.Connected(); len(got) != 1 {
		t.Errorf("connected = %v", got)
	}
}
