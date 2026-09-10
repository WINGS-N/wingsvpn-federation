package xrayapi

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	xraypb "wingsnet.org/federation/gen/xraypb"
)

type fakeStats struct {
	xraypb.UnimplementedStatsServiceServer
	stats     []*xraypb.Stat
	lastReset bool
}

func (f *fakeStats) QueryStats(_ context.Context, req *xraypb.QueryStatsRequest) (*xraypb.QueryStatsResponse, error) {
	f.lastReset = req.GetReset_()
	return &xraypb.QueryStatsResponse{Stat: f.stats}, nil
}

type fakeHandler struct {
	xraypb.UnimplementedHandlerServiceServer
	lastTag string
	lastOp  *xraypb.TypedMessage
}

func (f *fakeHandler) AlterInbound(_ context.Context, req *xraypb.AlterInboundRequest) (*xraypb.AlterInboundResponse, error) {
	f.lastTag = req.GetTag()
	f.lastOp = req.GetOperation()
	return &xraypb.AlterInboundResponse{}, nil
}

func serve(t *testing.T) (*Client, *fakeStats, *fakeHandler) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stats, handler := &fakeStats{}, &fakeHandler{}
	srv := grpc.NewServer()
	xraypb.RegisterStatsServiceServer(srv, stats)
	xraypb.RegisterHandlerServiceServer(srv, handler)
	go func() { _ = srv.Serve(lis) }()

	c := New(lis.Addr().String())
	t.Cleanup(func() {
		_ = c.Close()
		srv.Stop()
	})
	return c, stats, handler
}

func stat(name string, value int64) *xraypb.Stat {
	return &xraypb.Stat{Name: name, Value: value}
}

func TestQueryTrafficSplitsUsersFromInbounds(t *testing.T) {
	c, stats, _ := serve(t)
	stats.stats = []*xraypb.Stat{
		stat("user>>>f-1a2b3c4d>>>traffic>>>uplink", 100),
		stat("user>>>f-1a2b3c4d>>>traffic>>>downlink", 900),
		stat("user>>>f-deadbeef>>>traffic>>>uplink", 5),
		stat("inbound>>>fed-tcp>>>traffic>>>uplink", 105),
		stat("inbound>>>fed-tcp>>>traffic>>>downlink", 900),
	}
	got, err := c.QueryTraffic(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Users["f-1a2b3c4d"] != (Counter{Up: 100, Down: 900}) {
		t.Errorf("user counter = %+v", got.Users["f-1a2b3c4d"])
	}
	if got.Inbounds["fed-tcp"] != (Counter{Up: 105, Down: 900}) {
		t.Errorf("inbound counter = %+v", got.Inbounds["fed-tcp"])
	}
	// Adding both sides would bill the same bytes twice
	if got.Total != (Counter{Up: 105, Down: 900}) {
		t.Errorf("total = %+v, want the user side only", got.Total)
	}
}

// The 1 Hz path must not reset: the head derives deltas, so a reset would turn a
// dropped sample into lost traffic instead of a harmless gap
func TestQueryTrafficPassesResetThrough(t *testing.T) {
	c, stats, _ := serve(t)
	if _, err := c.QueryTraffic(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if stats.lastReset {
		t.Error("reset was requested when the caller asked not to")
	}
	if _, err := c.QueryTraffic(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !stats.lastReset {
		t.Error("reset was not passed through")
	}
}

func TestGarbageCounterNamesAreIgnored(t *testing.T) {
	c, stats, _ := serve(t)
	stats.stats = []*xraypb.Stat{
		stat("outbound>>>direct>>>traffic>>>uplink", 10),
		stat("user>>>x>>>traffic", 10),
		stat("user>>>x>>>traffic>>>sideways", 10),
		stat("user>>>x>>>traffic>>>uplink", -5),
		stat("", 10),
	}
	got, err := c.QueryTraffic(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Users) != 0 || got.Total != (Counter{}) {
		t.Errorf("garbage got through: %+v", got)
	}
}

// The type name and field numbers have to match the core exactly, because the
// core resolves the account against its own registry by full proto name
func TestAddUserBuildsAnAccountTheCoreCanDecode(t *testing.T) {
	c, _, handler := serve(t)
	if err := c.AddUser(context.Background(), "fed-tcp", "f-1a2b3c4d", "uuid-1", "xtls-rprx-vision", 0); err != nil {
		t.Fatal(err)
	}
	if handler.lastTag != "fed-tcp" {
		t.Errorf("tag = %q", handler.lastTag)
	}
	if handler.lastOp.GetType() != "xray.app.proxyman.command.AddUserOperation" {
		t.Fatalf("operation type = %q", handler.lastOp.GetType())
	}
	var op xraypb.AddUserOperation
	if err := proto.Unmarshal(handler.lastOp.GetValue(), &op); err != nil {
		t.Fatal(err)
	}
	if op.GetUser().GetEmail() != "f-1a2b3c4d" {
		t.Errorf("email = %q", op.GetUser().GetEmail())
	}
	if op.GetUser().GetAccount().GetType() != vlessAccountType {
		t.Fatalf("account type = %q", op.GetUser().GetAccount().GetType())
	}
	var acc xraypb.Account
	if err := proto.Unmarshal(op.GetUser().GetAccount().GetValue(), &acc); err != nil {
		t.Fatal(err)
	}
	if acc.GetId() != "uuid-1" || acc.GetFlow() != "xtls-rprx-vision" {
		t.Errorf("account = %+v", &acc)
	}
}

func TestRemoveUserRefusesAnEmptyEmail(t *testing.T) {
	c, _, handler := serve(t)
	if err := c.RemoveUser(context.Background(), "fed-tcp", ""); err == nil {
		t.Fatal("an empty email was accepted, which reads like a wildcard")
	}
	if handler.lastTag != "" {
		t.Error("the call reached the core anyway")
	}
	if err := c.AddUser(context.Background(), "fed-tcp", "", "u", "", 0); err == nil {
		t.Fatal("AddUser accepted an empty email")
	}
}

func TestRemoveUserSendsTheRemoveOperation(t *testing.T) {
	c, _, handler := serve(t)
	if err := c.RemoveUser(context.Background(), "fed-xhttp", "f-deadbeef"); err != nil {
		t.Fatal(err)
	}
	if handler.lastOp.GetType() != "xray.app.proxyman.command.RemoveUserOperation" {
		t.Fatalf("operation type = %q", handler.lastOp.GetType())
	}
	var op xraypb.RemoveUserOperation
	if err := proto.Unmarshal(handler.lastOp.GetValue(), &op); err != nil {
		t.Fatal(err)
	}
	if op.GetEmail() != "f-deadbeef" {
		t.Errorf("email = %q", op.GetEmail())
	}
}
