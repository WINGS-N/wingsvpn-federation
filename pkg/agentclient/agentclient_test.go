package agentclient

import (
	"context"
	"net"
	"testing"
	"time"
	"wingsnet.org/federation/internal/dialpick"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/agent/supervisor"
)

// The supervisor has to satisfy the optional reporter, or the head never learns
// the node's public key and cannot build a share link
func TestSupervisorReportsIdentity(t *testing.T) {
	var _ Executor = (*supervisor.Supervisor)(nil)
	if _, ok := any((*supervisor.Supervisor)(nil)).(IdentityReporter); !ok {
		t.Error("the supervisor no longer reports its public identity")
	}
}

// A reconnect must tell the head what is already applied. Without this the head
// sees version 0, pushes the config again and the agent restarts Xray, dropping
// every live connection on a donated box for no reason
func TestSupervisorReportsItsConfigVersion(t *testing.T) {
	if _, ok := any((*supervisor.Supervisor)(nil)).(ConfigVersioner); !ok {
		t.Error("the supervisor no longer reports its applied config version")
	}
}

type stubExecutor struct {
	version uint64
}

func (s *stubExecutor) ApplyConfig(context.Context, *fedpb.NodeConfig) ([]string, error) {
	return nil, nil
}
func (s *stubExecutor) ApplyProfiles(context.Context, *fedpb.ProfileDelta) error { return nil }
func (s *stubExecutor) Sample(context.Context) (*fedpb.StatsSample, error) {
	return &fedpb.StatsSample{}, nil
}
func (s *stubExecutor) Health(context.Context) (*fedpb.Heartbeat, error) {
	return &fedpb.Heartbeat{}, nil
}
func (s *stubExecutor) SetRotationState(fedpb.RotationState) error { return nil }
func (s *stubExecutor) ConfigVersion() uint64                      { return s.version }

// fakeHead captures the first Hello and then hangs up
type fakeHead struct {
	fedpb.UnimplementedFederationServer
	hello chan *fedpb.Hello
}

func (f *fakeHead) Session(stream fedpb.Federation_SessionServer) error {
	frame, err := stream.Recv()
	if err != nil {
		return err
	}
	f.hello <- frame.GetHello()
	return nil
}

func TestHelloCarriesTheAppliedConfigVersion(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	head := &fakeHead{hello: make(chan *fedpb.Hello, 1)}
	srv := grpc.NewServer()
	fedpb.RegisterFederationServer(srv, head)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	cfg := Config{
		HeadEndpoint: lis.Addr().String(),
		NodeID:       "node-1",
		NodeSecret:   "secret",
		BootID:       "boot-1",
		Dial: func(_ context.Context, endpoint string) (*grpc.ClientConn, error) {
			return grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
		},
	}
	cfg.applyDefaults()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = runOnce(ctx, cfg, &stubExecutor{version: 7}, dialpick.New(cfg.HeadEndpoint)) }()

	select {
	case hello := <-head.hello:
		if hello.GetConfigVersion() != 7 {
			t.Errorf("hello config version = %d, want 7", hello.GetConfigVersion())
		}
	case <-ctx.Done():
		t.Fatal("no hello arrived")
	}
}
