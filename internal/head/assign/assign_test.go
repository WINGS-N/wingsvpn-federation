package assign

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
)

var now = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

type nodeOpt func(*registry.Node)

func withDonor(id string) nodeOpt   { return func(n *registry.Node) { n.DonorID = id } }
func withUsed(u uint64) nodeOpt     { return func(n *registry.Node) { n.UsedBytes = u } }
func withSessions(s uint32) nodeOpt { return func(n *registry.Node) { n.Sessions = s } }
func withState(s fedpb.RotationState) nodeOpt {
	return func(n *registry.Node) { n.State = s }
}
func withAddr(addr string, v6 bool) nodeOpt {
	return func(n *registry.Node) {
		n.Passport = &fedpb.NodePassport{Addresses: []*fedpb.NodeAddress{{Address: addr, Ipv6: v6}}}
	}
}
func stale() nodeOpt { return func(n *registry.Node) { n.LastSeen = now.Add(-time.Minute) } }

func node(id string, opts ...nodeOpt) *registry.Node {
	n := &registry.Node{
		ID:                  id,
		DonorID:             "donor-" + id,
		DeclaredBudgetBytes: 1000,
		State:               fedpb.RotationState_ROTATION_STATE_ACTIVE,
		PeriodStart:         time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:            now,
		Health:              registry.Health{Uptime: 30 * 24 * 3600, CPUPct: 0, At: now},
		// A distinct /24 per node by default, or the spread rule would collapse
		// every fixture into one candidate and the tests would test nothing
		Passport: &fedpb.NodePassport{
			Addresses: []*fedpb.NodeAddress{{Address: fmt.Sprintf("203.0.%d.10", int(id[len(id)-1]))}},
		},
	}
	for _, o := range opts {
		o(n)
	}
	return n
}

// The burn-rate defence is a scoring term, not a separate rule: a node running
// ahead of its own pledge has to shed load before it hits the wall
func TestPaceFallsWhenANodeBurnsAhead(t *testing.T) {
	// Half the month gone, half the budget spent: exactly on track
	onTrack := node("n1", withUsed(500))
	onTrack.PeriodStart = now.AddDate(0, 0, -15)
	// Same spend in a single day
	burning := node("n2", withUsed(500))
	burning.PeriodStart = now.AddDate(0, 0, -1)

	slow := ScoreNode(onTrack, now, Options{})
	fast := ScoreNode(burning, now, Options{})
	if fast.Pace >= slow.Pace {
		t.Errorf("pace: burning %.3f, on track %.3f - burning must score worse", fast.Pace, slow.Pace)
	}
	if fast.Total >= slow.Total {
		t.Errorf("total: burning %.3f, on track %.3f", fast.Total, slow.Total)
	}
}

// A few minutes of traffic must not project a whole month and park a fresh node
func TestPaceDoesNotPunishTheStartOfAPeriod(t *testing.T) {
	n := node("n1", withUsed(1))
	n.PeriodStart = now.Add(-time.Minute)
	if got := ScoreNode(n, now, Options{}).Pace; got < 0.9 {
		t.Errorf("pace = %.3f a minute into the period, want it near 1", got)
	}
}

func TestStaleNodeScoresZeroAndIsNotHandedOut(t *testing.T) {
	n := node("n1", stale())
	score := ScoreNode(n, now, Options{})
	if score.Fresh || score.Total != 0 {
		t.Errorf("stale node scored %+v", score)
	}
	if got := Eligible([]*registry.Node{n}, now, Options{}); len(got) != 0 {
		t.Errorf("a stale node was eligible: %v", got)
	}
}

func TestRotationStates(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *registry.Node
		want fedpb.RotationState
	}{
		{"healthy", node("n1"), fedpb.RotationState_ROTATION_STATE_ACTIVE},
		{"near budget", node("n2", withUsed(900)), fedpb.RotationState_ROTATION_STATE_DRAINING},
		{"budget spent", node("n3", withUsed(990)), fedpb.RotationState_ROTATION_STATE_PARKED},
		{"silent", node("n4", stale()), fedpb.RotationState_ROTATION_STATE_PARKED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			score := ScoreNode(tc.node, now, Options{})
			got, _ := NextState(tc.node, score, now, Options{})
			if got != tc.want {
				t.Errorf("state = %v, want %v (score %+v)", got, tc.want, score)
			}
		})
	}
}

// Quarantine is a judgement. Arithmetic may not undo it, or a node cut off for
// abuse would walk straight back in as soon as its counters looked fine
func TestQuarantineIsNeverLiftedByScoring(t *testing.T) {
	n := node("n1", withState(fedpb.RotationState_ROTATION_STATE_QUARANTINED))
	n.Reason = "abuse"
	got, reason := NextState(n, ScoreNode(n, now, Options{}), now, Options{})
	if got != fedpb.RotationState_ROTATION_STATE_QUARANTINED || reason != "abuse" {
		t.Errorf("state = %v %q, want the quarantine kept", got, reason)
	}
}

// Draining means no new users and existing ones untouched, so it must not be
// handed out - and must not be treated as dead either
func TestDrainingNodeIsNotHandedOut(t *testing.T) {
	n := node("n1", withState(fedpb.RotationState_ROTATION_STATE_DRAINING))
	if got := Eligible([]*registry.Node{n}, now, Options{}); len(got) != 0 {
		t.Errorf("a draining node was offered to a new user")
	}
}

// A v6-only node is unreachable for almost every user however good it looks
func TestNodeWithoutIPv4IsUnreachable(t *testing.T) {
	n := node("n1", withAddr("2001:db8::1", true))
	if got := Eligible([]*registry.Node{n}, now, Options{}); len(got) != 0 {
		t.Errorf("a v6-only node was handed out")
	}
}

// Two nodes that fail together are one node. Same donor or same /24 means one
// provider suspension takes both, which defeats having a second
func TestPickSpreadsAcrossDonorsAndSubnets(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	nodes := []*registry.Node{
		node("a1", withDonor("same")),
		node("a2", withDonor("same")),
		node("a3", withDonor("other")),
	}
	got := Pick(nodes, now, Options{}, Request{Want: 2, Rand: rng})
	if len(got) != 2 {
		t.Fatalf("picked %d nodes, want 2", len(got))
	}
	if got[0].DonorID == got[1].DonorID {
		t.Errorf("both nodes came from donor %s", got[0].DonorID)
	}

	sameSubnet := []*registry.Node{
		node("b1", withDonor("d1"), withAddr("198.51.100.7", false)),
		node("b2", withDonor("d2"), withAddr("198.51.100.9", false)),
	}
	if got := Pick(sameSubnet, now, Options{}, Request{Want: 2, Rand: rng}); len(got) != 1 {
		t.Errorf("picked %d nodes from one /24, want 1", len(got))
	}
}

// Reshuffling on every subscription refresh breaks live clients for nothing
func TestPickKeepsWhatTheUserAlreadyHas(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	nodes := []*registry.Node{node("n1"), node("n2"), node("n3"), node("n4")}
	first := Pick(nodes, now, Options{}, Request{Want: 2, Rand: rng})
	ids := []string{first[0].ID, first[1].ID}

	for i := 0; i < 5; i++ {
		again := Pick(nodes, now, Options{}, Request{Want: 2, Sticky: ids, Rand: rng})
		if len(again) != 2 || again[0].ID != ids[0] || again[1].ID != ids[1] {
			t.Fatalf("refresh %d moved the user: %v -> %v", i, ids, idsOf(again))
		}
	}
}

// A sticky node that went away must be replaced rather than kept as a hole
func TestPickReplacesAStickyNodeThatWentAway(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	nodes := []*registry.Node{node("n1"), node("n2", stale()), node("n3")}
	got := Pick(nodes, now, Options{}, Request{Want: 2, Sticky: []string{"n1", "n2"}, Rand: rng})
	if len(got) != 2 {
		t.Fatalf("picked %v, want two nodes", idsOf(got))
	}
	for _, n := range got {
		if n.ID == "n2" {
			t.Error("a stale sticky node was kept")
		}
	}
}

// One donor must not carry the whole federation just for scoring best once
func TestPickSpreadsLoadAcrossTheTopOfTheList(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	var nodes []*registry.Node
	for i := 0; i < 6; i++ {
		nodes = append(nodes, node(fmt.Sprintf("n%d", i), withDonor(fmt.Sprintf("d%d", i)), withSessions(uint32(i))))
	}
	counts := map[string]int{}
	for i := 0; i < 200; i++ {
		for _, n := range Pick(nodes, now, Options{}, Request{Want: 2, Rand: rng}) {
			counts[n.ID]++
		}
	}
	if len(counts) < 4 {
		t.Errorf("only %d distinct nodes ever picked: %v", len(counts), counts)
	}
	best := node("n0")
	if counts[best.ID] >= 200 {
		t.Errorf("the top node took every single assignment: %v", counts)
	}
}

func TestSubnetOfIgnoresAPort(t *testing.T) {
	n := node("n1", withAddr("203.0.113.42:443", false))
	if got := subnetOf(n, now, Options{}.withDefaults()); got != "203.0.113.0" {
		t.Errorf("subnet = %q, want 203.0.113.0", got)
	}
	if ip := ipv4Of(n, now, Options{}.withDefaults()); !ip.Equal(net.ParseIP("203.0.113.42").To4()) {
		t.Errorf("ip = %v", ip)
	}
}

func idsOf(nodes []*registry.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

func withProbe(addr, transport string, ok bool, rtt uint32, age time.Duration) nodeOpt {
	return func(n *registry.Node) {
		if n.Reachability == nil {
			n.Reachability = map[string]registry.Reachability{}
		}
		n.Reachability[registry.ReachKey(addr, transport)] = registry.Reachability{
			Address: addr, Transport: transport, OK: ok, RTTMs: rtt,
			DownloadBps: 5_000_000, At: now.Add(-age),
		}
	}
}

// The node's own claim proves nothing behind NAT or after a provider nulls a
// route. What a vantage point actually reached is the answer
func TestAProbeVerifiedAddressIsPreferred(t *testing.T) {
	n := node("n1", withAddr("203.0.113.9", false), withProbe("198.51.100.4", "tcp", true, 50, time.Minute))
	got := ipv4Of(n, now, Options{}.withDefaults())
	if got.String() != "198.51.100.4" {
		t.Errorf("address = %v, want the probe-verified one", got)
	}
}

// A route that worked last week says nothing about a route blocked today
func TestAStaleProbeStopsCountingAsProof(t *testing.T) {
	n := node("n1", withAddr("203.0.113.9", false), withProbe("198.51.100.4", "tcp", true, 50, 48*time.Hour))
	opts := Options{RequireProbe: true}.withDefaults()
	opts.RequireProbe = true
	if got := ipv4Of(n, now, opts); got != nil {
		t.Errorf("address = %v, want nothing from a stale measurement", got)
	}
}

// A federation with no vantage point deployed must still work, or turning the
// requirement on by default would park the whole fleet
func TestWithoutAnyProbeTheSelfReportedAddressIsUsed(t *testing.T) {
	n := node("n1", withAddr("203.0.113.9", false))
	if got := ipv4Of(n, now, Options{}.withDefaults()); got.String() != "203.0.113.9" {
		t.Errorf("address = %v, want the self-reported one", got)
	}
	opts := Options{}.withDefaults()
	opts.RequireProbe = true
	if got := ipv4Of(n, now, opts); got != nil {
		t.Errorf("address = %v, want nothing once proof is required", got)
	}
}

// A node can report a bored CPU and still be unusable from where the users are
func TestMeasuredLatencyMovesHealth(t *testing.T) {
	fast := node("n1", withProbe("203.0.113.49", "tcp", true, 30, time.Minute))
	slow := node("n2", withProbe("203.0.113.50", "tcp", true, 600, time.Minute))
	fastScore := ScoreNode(fast, now, Options{})
	slowScore := ScoreNode(slow, now, Options{})
	if slowScore.Health >= fastScore.Health {
		t.Errorf("health: 600ms %.3f, 30ms %.3f - latency must count", slowScore.Health, fastScore.Health)
	}
	// An unmeasured node is scored on what it says about itself, not punished
	unmeasured := ScoreNode(node("n3"), now, Options{})
	if unmeasured.Health <= slowScore.Health {
		t.Errorf("an unmeasured node (%.3f) scored no better than a slow one (%.3f)",
			unmeasured.Health, slowScore.Health)
	}
}

// One provider suspension must not take both of a user's nodes
func TestSpreadKeepsNodesOffOneDeclaredNetwork(t *testing.T) {
	withASN := func(asn string) nodeOpt {
		return func(n *registry.Node) { n.Passport.Asn = asn }
	}
	rng := rand.New(rand.NewSource(5))
	nodes := []*registry.Node{
		node("a1", withDonor("d1"), withASN("AS64500")),
		node("a2", withDonor("d2"), withASN("AS64500")),
		node("a3", withDonor("d3"), withASN("AS64501")),
	}
	got := Pick(nodes, now, Options{}, Request{Want: 2, Rand: rng})
	if len(got) != 2 {
		t.Fatalf("picked %v", idsOf(got))
	}
	if got[0].Passport.GetAsn() == got[1].Passport.GetAsn() {
		t.Errorf("both nodes sit on %s", got[0].Passport.GetAsn())
	}
}
