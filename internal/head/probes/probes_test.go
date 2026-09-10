package probes

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
)

var at = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

type fakePusher struct {
	added map[string][]*fedpb.ProfileSpec
	fail  bool
}

func (f *fakePusher) PushProfiles(nodeID string, add []*fedpb.ProfileSpec, _ []string) error {
	if f.fail {
		return errNope
	}
	if f.added == nil {
		f.added = map[string][]*fedpb.ProfileSpec{}
	}
	f.added[nodeID] = append(f.added[nodeID], add...)
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

const errNope = errString("node refused")

func testConfig(string) *fedpb.NodeConfig {
	return &fedpb.NodeConfig{
		Reality: &fedpb.RealityIdentity{ServerNames: []string{"www.example.com"}, ShortIds: []string{"abcd"}},
		Inbounds: []*fedpb.InboundSpec{
			{Tag: "fed-tcp", Network: "tcp", Port: 443, Flow: "xtls-rprx-vision", Reality: true},
			{Tag: "fed-xhttp", Network: "xhttp", Port: 8443, Reality: true,
				Xhttp: &fedpb.XhttpSpec{Path: "/dl"}},
		},
	}
}

func setup(t *testing.T, nodes ...*registry.Node) (*Fleet, *registry.Registry, *fakePusher) {
	t.Helper()
	reg := registry.New()
	reg.SetNow(func() time.Time { return at })
	for _, n := range nodes {
		reg.Add(n)
	}
	push := &fakePusher{}
	f := New(reg, push, testConfig)
	f.now = func() time.Time { return at }
	return f, reg, push
}

func node(id string, opts ...func(*registry.Node)) *registry.Node {
	n := &registry.Node{
		ID: id, Secret: "s", DonorID: "d-" + id,
		State:            fedpb.RotationState_ROTATION_STATE_ACTIVE,
		LastSeen:         at,
		RealityPublicKey: "PBK-" + id,
		Mldsa65Verify:    "PQV-" + id,
		Passport: &fedpb.NodePassport{Addresses: []*fedpb.NodeAddress{
			{Address: "203.0.113.1"},
			{Address: "198.51.100.1", Source: "configured"},
		}},
	}
	for _, o := range opts {
		o(n)
	}
	return n
}

// Every candidate address is measured, not just the first: a node often has
// several and only some of them actually carry traffic
func TestEveryAddressAndTransportIsMeasured(t *testing.T) {
	f, _, _ := setup(t, node("n1"))
	task := f.Targets()
	if len(task.GetTargets()) != 4 {
		t.Fatalf("got %d targets, want two addresses times two transports", len(task.GetTargets()))
	}
	seen := map[string]bool{}
	for _, target := range task.GetTargets() {
		seen[target.GetHost()+"/"+target.GetTransport()] = true
		if target.GetRealityPublicKey() != "PBK-n1" {
			t.Errorf("target lacks the node identity: %+v", target)
		}
		// The fleet is not signing post-quantum, so a probe expecting a
		// signature would report a perfectly good node as unreachable
		if target.GetMldsa65Verify() != "" {
			t.Errorf("probe told to expect a signature the node is not making: %+v", target)
		}
		if target.GetDownloadUrl() == "" || target.GetDownloadBytes() == 0 {
			t.Errorf("target has nothing to pull: %+v", target)
		}
	}
	for _, want := range []string{"203.0.113.1/tcp", "203.0.113.1/xhttp", "198.51.100.1/tcp", "198.51.100.1/xhttp"} {
		if !seen[want] {
			t.Errorf("never measured %s", want)
		}
	}
}

// The probe's credential is minted once and reused. Adding and removing a user
// on somebody else's server every few minutes is a lot of churn to buy nothing
func TestTheProbeProfileIsMintedOnce(t *testing.T) {
	f, _, push := setup(t, node("n1"))
	first := f.Targets()
	second := f.Targets()
	if got := len(push.added["n1"]); got != 2 {
		t.Fatalf("pushed %d entries, want one per inbound exactly once", got)
	}
	if first.GetTargets()[0].GetUuid() != second.GetTargets()[0].GetUuid() {
		t.Error("the probe credential changed between rounds")
	}
}

// Measuring is our own traffic, and billing a donor for it would be dishonest
func TestTheProbeProfileIsNotMetered(t *testing.T) {
	f, _, push := setup(t, node("n1"))
	f.Targets()
	for _, spec := range push.added["n1"] {
		if spec.GetMetered() {
			t.Error("the probe's own traffic is billed to the donor")
		}
	}
}

// A quarantined node is not going to be handed out whatever the numbers say, and
// measuring it spends a donor's traffic for nothing
func TestQuarantinedAndSilentNodesAreNotMeasured(t *testing.T) {
	quarantined := node("n1", func(n *registry.Node) {
		n.State = fedpb.RotationState_ROTATION_STATE_QUARANTINED
	})
	silent := node("n2", func(n *registry.Node) { n.LastSeen = at.Add(-time.Hour) })
	noIdentity := node("n3", func(n *registry.Node) { n.RealityPublicKey = "" })
	f, _, _ := setup(t, quarantined, silent, noIdentity)
	if got := f.Targets(); len(got.GetTargets()) != 0 {
		t.Errorf("measured %d targets, want none", len(got.GetTargets()))
	}
}

// A node that refuses the probe profile cannot be measured through it, and
// handing out a target with a credential that does not exist measures nothing
func TestANodeThatRefusesIsNotTargeted(t *testing.T) {
	f, _, push := setup(t, node("n1"))
	push.fail = true
	if got := f.Targets(); len(got.GetTargets()) != 0 {
		t.Errorf("targeted a node that refused the profile: %+v", got.GetTargets())
	}
}

func TestReportsLandOnTheNode(t *testing.T) {
	f, reg, _ := setup(t, node("n1"))
	f.Ingest("probe-ru", &fedpb.ProbeReport{
		NodeId: "n1", Address: "198.51.100.1", Transport: "tcp",
		HandshakeOk: true, RttMs: 55, DownloadBps: 9_000_000,
		MeasuredUnix: at.Unix(),
	})
	n, _ := reg.Get("n1")
	got, ok := n.Reachability[registry.ReachKey("198.51.100.1", "tcp")]
	if !ok {
		t.Fatalf("report not filed: %+v", n.Reachability)
	}
	if !got.OK || got.RTTMs != 55 || got.ProbeID != "probe-ru" {
		t.Errorf("filed = %+v", got)
	}
	if verified := n.VerifiedAddresses(at, time.Hour); len(verified) != 1 || verified[0] != "198.51.100.1" {
		t.Errorf("verified = %v, want only the measured address", verified)
	}
	// A report for a node that has gone must not panic or invent one
	f.Ingest("probe-ru", &fedpb.ProbeReport{NodeId: "nope"})
}

// tcp and xhttp are blocked independently, so a node usually loses one and keeps
// the other rather than dying outright
func TestOnlyTheWorkingTransportIsRecorded(t *testing.T) {
	f, reg, _ := setup(t, node("n1"))
	f.Ingest("p", &fedpb.ProbeReport{NodeId: "n1", Address: "203.0.113.1", Transport: "tcp", HandshakeOk: true, MeasuredUnix: at.Unix()})
	f.Ingest("p", &fedpb.ProbeReport{NodeId: "n1", Address: "203.0.113.1", Transport: "xhttp", HandshakeOk: false, Error: "timeout", MeasuredUnix: at.Unix()})
	n, _ := reg.Get("n1")
	working := n.WorkingTransports(at, time.Hour)
	if len(working) != 1 || working[0] != "tcp" {
		t.Errorf("working = %v, want only tcp", working)
	}
}

// And when the fleet does sign, the probe has to know, or it measures a failure
// that is not there
func TestProbeIsToldAboutPostQuantumWhenItIsOn(t *testing.T) {
	reg := registry.New()
	reg.SetNow(func() time.Time { return at })
	reg.Add(node("n1"))
	f := New(reg, &fakePusher{}, func(string) *fedpb.NodeConfig {
		cfg := testConfig("")
		cfg.Reality.PostQuantum = true
		return cfg
	})
	f.now = func() time.Time { return at }
	for _, target := range f.Targets().GetTargets() {
		if target.GetMldsa65Verify() != "PQV-n1" {
			t.Errorf("target lacks the verify half: %+v", target)
		}
	}
}
