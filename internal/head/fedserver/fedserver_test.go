package fedserver

import (
	"context"
	"errors"
	"testing"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
)

type fakeTokens struct {
	donor  string
	used   bool
	reject bool
}

func (f *fakeTokens) Redeem(string) (string, error) {
	if f.reject || f.used {
		return "", errors.New("rejected")
	}
	f.used = true
	return f.donor, nil
}

func newServer(t *testing.T, tok *fakeTokens) (*Server, *registry.Registry) {
	t.Helper()
	reg := registry.New()
	return New(reg, tok, "head.example:9310"), reg
}

func joinReq(fingerprint string) *fedpb.JoinRequest {
	return &fedpb.JoinRequest{
		EnrollToken:                "tok",
		NodeFingerprint:            fingerprint,
		DeclaredMonthlyBudgetBytes: 1 << 40,
		Passport:                   &fedpb.NodePassport{Hostname: "node-1"},
	}
}

func TestJoinEnrollsAndIssuesCredentials(t *testing.T) {
	s, reg := newServer(t, &fakeTokens{donor: "donor-1"})
	resp, err := s.Join(context.Background(), joinReq("fp-1"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetNodeId() == "" || resp.GetNodeSecret() == "" {
		t.Fatal("join returned no credentials")
	}
	if resp.GetHeadEndpoint() != "head.example:9310" {
		t.Errorf("head endpoint = %q", resp.GetHeadEndpoint())
	}
	node, err := reg.Get(resp.GetNodeId())
	if err != nil {
		t.Fatal(err)
	}
	if node.DonorID != "donor-1" {
		t.Errorf("donor = %q, want donor-1", node.DonorID)
	}
	// A self-reported address proves nothing behind NAT, so a fresh node must not
	// be usable until the head has probed it
	if node.State != fedpb.RotationState_ROTATION_STATE_PARKED {
		t.Errorf("state = %v, want PARKED until probed", node.State)
	}
}

// Somebody always pastes the placeholder straight out of the docs
func TestJoinRejectsPlaceholderToken(t *testing.T) {
	s, _ := newServer(t, &fakeTokens{donor: "d"})
	req := joinReq("fp-1")
	req.EnrollToken = "<token>"
	if _, err := s.Join(context.Background(), req); err == nil {
		t.Error("placeholder token was accepted")
	}
}

func TestJoinRequiresTokenAndFingerprint(t *testing.T) {
	s, _ := newServer(t, &fakeTokens{donor: "d"})
	req := joinReq("fp-1")
	req.EnrollToken = ""
	if _, err := s.Join(context.Background(), req); err == nil {
		t.Error("empty token accepted")
	}
	req = joinReq("")
	if _, err := s.Join(context.Background(), req); err == nil {
		t.Error("empty fingerprint accepted")
	}
}

func TestJoinRejectsSpentToken(t *testing.T) {
	tok := &fakeTokens{donor: "d"}
	s, _ := newServer(t, tok)
	if _, err := s.Join(context.Background(), joinReq("fp-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Join(context.Background(), joinReq("fp-2")); err == nil {
		t.Error("a spent token enrolled a second node")
	}
}

// Re-running the installer must not fork a second identity keeping its own
// budget, so the same machine replaces its earlier enrollment
func TestReenrollmentReplacesTheSameMachine(t *testing.T) {
	tok := &fakeTokens{donor: "d"}
	s, reg := newServer(t, tok)
	first, err := s.Join(context.Background(), joinReq("fp-same"))
	if err != nil {
		t.Fatal(err)
	}
	tok.used = false
	second, err := s.Join(context.Background(), joinReq("fp-same"))
	if err != nil {
		t.Fatal(err)
	}
	if first.GetNodeId() == second.GetNodeId() {
		t.Fatal("the second enrollment reused the node id, so nothing was tested")
	}
	if _, err := reg.Get(first.GetNodeId()); err == nil {
		t.Error("the previous enrollment of the same machine survived")
	}
	if _, err := reg.Get(second.GetNodeId()); err != nil {
		t.Error("the new enrollment is missing")
	}
}

// Two nodes must never share a secret, and a secret must never be the node id
func TestCredentialsAreDistinct(t *testing.T) {
	tok := &fakeTokens{donor: "d"}
	s, _ := newServer(t, tok)
	a, err := s.Join(context.Background(), joinReq("fp-a"))
	if err != nil {
		t.Fatal(err)
	}
	tok.used = false
	b, err := s.Join(context.Background(), joinReq("fp-b"))
	if err != nil {
		t.Fatal(err)
	}
	if a.GetNodeSecret() == b.GetNodeSecret() {
		t.Error("two nodes were issued the same secret")
	}
	if a.GetNodeId() == a.GetNodeSecret() {
		t.Error("node id and secret are the same value")
	}
}
