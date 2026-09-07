package rotation

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/assign"
	"wingsnet.org/federation/internal/head/registry"
)

type pushRecord struct {
	nodeID string
	state  fedpb.RotationState
	reason string
}

type fakePusher struct {
	pushes []pushRecord
	err    error
}

func (f *fakePusher) PushRotation(nodeID string, state fedpb.RotationState, reason string) error {
	f.pushes = append(f.pushes, pushRecord{nodeID, state, reason})
	return f.err
}

func setup(t *testing.T, at time.Time) (*registry.Registry, *fakePusher, *Rotator) {
	t.Helper()
	reg := registry.New()
	reg.SetNow(func() time.Time { return at })
	push := &fakePusher{}
	rot := New(reg, push, assign.Options{})
	rot.now = func() time.Time { return at }
	return reg, push, rot
}

func healthyNode(id string, budget, used uint64, at time.Time) *registry.Node {
	return &registry.Node{
		ID:                  id,
		Secret:              "s",
		DonorID:             "d-" + id,
		DeclaredBudgetBytes: budget,
		UsedBytes:           used,
		State:               fedpb.RotationState_ROTATION_STATE_ACTIVE,
		PeriodStart:         time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, at.Location()),
		LastSeen:            at,
		Health:              registry.Health{Uptime: 30 * 24 * 3600, At: at},
		Passport: &fedpb.NodePassport{
			Addresses: []*fedpb.NodeAddress{{Address: "203.0.113.5"}},
		},
	}
}

// A node approaching its pledge stops taking new users but keeps the ones it
// has: cutting a live connection to save a donor a few gigabytes costs the user
// far more than it saves
func TestNodeNearItsBudgetDrainsAndIsToldSo(t *testing.T) {
	at := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	reg, push, rot := setup(t, at)
	reg.Add(healthyNode("n1", 1000, 900, at))

	changes := rot.Tick()
	if len(changes) != 1 || changes[0].To != fedpb.RotationState_ROTATION_STATE_DRAINING {
		t.Fatalf("changes = %+v, want a move to draining", changes)
	}
	if len(push.pushes) != 1 || push.pushes[0].state != fedpb.RotationState_ROTATION_STATE_DRAINING {
		t.Fatalf("pushes = %+v", push.pushes)
	}
	n, _ := reg.Get("n1")
	if n.State != fedpb.RotationState_ROTATION_STATE_DRAINING {
		t.Errorf("registry state = %v", n.State)
	}

	// Nothing changed on the next pass, so nothing is pushed again
	if changes := rot.Tick(); len(changes) != 0 {
		t.Errorf("a stable node was moved again: %+v", changes)
	}
	if len(push.pushes) != 1 {
		t.Errorf("the same state was pushed twice: %+v", push.pushes)
	}
}

// A spent pledge parks the node, and the month turning has to bring it back on
// its own - otherwise the federation empties out one donor at a time
func TestAParkedNodeComesBackWhenTheMonthTurns(t *testing.T) {
	march := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	reg, push, rot := setup(t, march)
	reg.Add(healthyNode("n1", 1000, 995, march))

	if changes := rot.Tick(); len(changes) != 1 || changes[0].To != fedpb.RotationState_ROTATION_STATE_PARKED {
		t.Fatalf("changes = %+v, want parked", changes)
	}

	april := time.Date(2026, 4, 1, 0, 0, 1, 0, time.UTC)
	reg.SetNow(func() time.Time { return april })
	rot.now = func() time.Time { return april }
	// The node is reporting again in the new month
	if err := reg.ApplyHeartbeat("n1", 0, 30*24*3600, "running", "ready"); err != nil {
		t.Fatal(err)
	}

	changes := rot.Tick()
	if len(changes) != 1 || changes[0].To != fedpb.RotationState_ROTATION_STATE_ACTIVE {
		t.Fatalf("changes = %+v, want the node back in rotation", changes)
	}
	n, _ := reg.Get("n1")
	if n.UsedBytes != 0 {
		t.Errorf("used = %d after the roll, want 0", n.UsedBytes)
	}
	if last := push.pushes[len(push.pushes)-1]; last.state != fedpb.RotationState_ROTATION_STATE_ACTIVE {
		t.Errorf("last push = %+v", last)
	}
}

// A node cut off for abuse must not walk back in because its counters look fine
func TestQuarantineSurvivesTheRotationLoop(t *testing.T) {
	at := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	reg, push, rot := setup(t, at)
	n := healthyNode("n1", 1000, 0, at)
	n.State = fedpb.RotationState_ROTATION_STATE_QUARANTINED
	n.Reason = "abuse"
	reg.Add(n)

	if changes := rot.Tick(); len(changes) != 0 {
		t.Fatalf("quarantine was lifted: %+v", changes)
	}
	if len(push.pushes) != 0 {
		t.Errorf("pushed something for a quarantined node: %+v", push.pushes)
	}
}

// A silent node is parked even though nobody can be told about it
func TestSilentNodeIsParkedWithoutASession(t *testing.T) {
	at := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	reg, push, rot := setup(t, at)
	n := healthyNode("n1", 1000, 0, at)
	n.LastSeen = at.Add(-time.Hour)
	reg.Add(n)
	push.err = errPushFailed

	changes := rot.Tick()
	if len(changes) != 1 || changes[0].To != fedpb.RotationState_ROTATION_STATE_PARKED {
		t.Fatalf("changes = %+v, want parked", changes)
	}
	if got, _ := reg.Get("n1"); got.State != fedpb.RotationState_ROTATION_STATE_PARKED {
		t.Errorf("state = %v, a push failure must not undo the decision", got.State)
	}
}

var errPushFailed = errTest("push failed")

type errTest string

func (e errTest) Error() string { return string(e) }
