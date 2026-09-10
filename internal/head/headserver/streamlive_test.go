package headserver

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/aggregator"
	"wingsnet.org/federation/internal/head/registry"
	"wingsnet.org/federation/internal/head/tokens"
)

func serveLive(t *testing.T) (headpb.FederationHeadClient, *registry.Registry, *aggregator.Aggregator) {
	t.Helper()
	reg, agg := registry.New(), aggregator.New()
	srv := New(reg, agg, tokens.New(), "fleet")
	// One frame per second is the shipped cadence; a test that waited for it
	// would spend its life asleep
	srv.liveInterval = 20 * time.Millisecond

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	headpb.RegisterFederationHeadServer(server, srv)
	go func() { _ = server.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
	})
	return headpb.NewFederationHeadClient(conn), reg, agg
}

// The stream is bidirectional so the panel can move between the fleet view, one
// donor and one node without dialing again
func TestStreamLiveSwitchesScopeOnTheSameStream(t *testing.T) {
	client, reg, agg := serveLive(t)
	addNode(reg, "n1", "d1", 4242)
	now := time.Now()
	agg.Ingest(aggregator.Sample{NodeID: "n1", DonorID: "d1", BootID: "b", At: now})
	agg.Ingest(aggregator.Sample{NodeID: "n1", DonorID: "d1", BootID: "b", UpBytes: 700, ActiveSessions: 2, At: now.Add(time.Second)})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.StreamLive(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := stream.Send(&headpb.LiveSubscribe{Scope: headpb.LiveScope_LIVE_SCOPE_GLOBAL}); err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if first.GetGlobal() == nil || first.GetGlobal().GetNodesOnline() != 1 {
		t.Fatalf("global frame = %+v", first)
	}
	if first.GetDonor() != nil || first.GetNode() != nil {
		t.Error("a global subscription leaked donor or node detail")
	}

	if err := stream.Send(&headpb.LiveSubscribe{
		Scope: headpb.LiveScope_LIVE_SCOPE_NODE, NodeId: "n1",
	}); err != nil {
		t.Fatal(err)
	}
	// The ticker may still deliver a global frame in flight, so read until the
	// scope actually changes rather than assuming the next one
	deadline := time.Now().Add(3 * time.Second)
	for {
		update, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if node := update.GetNode(); node != nil {
			if node.GetNodeId() != "n1" || node.GetDeclaredBudgetBytes() != 4242 {
				t.Errorf("node frame = %+v", node)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the stream never switched to the node scope")
		}
	}
}

// Nothing is pushed until the panel says what it wants, so a stream opened and
// left alone costs nothing
func TestStreamLiveSaysNothingBeforeSubscribing(t *testing.T) {
	client, _, _ := serveLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := client.StreamLive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *headpb.LiveUpdate, 1)
	go func() {
		update, err := stream.Recv()
		if err == nil {
			got <- update
		}
	}()
	select {
	case update := <-got:
		t.Fatalf("an unsubscribed stream was pushed %+v", update)
	case <-time.After(200 * time.Millisecond):
	}
}
