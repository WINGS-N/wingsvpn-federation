package enforce

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/oracle"
)

type fakeAlloc struct{ revoked []string }

func (f *fakeAlloc) Revoke(userID string) { f.revoked = append(f.revoked, userID) }

func setup(t *testing.T) (*Enforcer, *oracle.Judge, *fakeAlloc) {
	t.Helper()
	judge := oracle.NewJudge(oracle.NewRulesScorer())
	alloc := &fakeAlloc{}
	resolve := func(profileID string) (string, bool) {
		switch profileID {
		case "p-alice":
			return "alice", true
		case "p-bob":
			return "bob", true
		default:
			return "", false
		}
	}
	return New(judge, alloc, resolve), judge, alloc
}

func signal(profileID string, kind fedpb.AbuseKind, count uint32) *fedpb.AbuseSignal {
	return &fedpb.AbuseSignal{ProfileId: profileID, Kind: kind, Count: count}
}

// A node only knows the profile; the decision is about the person behind it
func TestASignalIsFiledAgainstTheUserNotTheProfile(t *testing.T) {
	e, judge, _ := setup(t)
	e.Observe(signal("p-alice", fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT, 1), "node-1")
	if got := judge.Accused(); len(got) != 1 || got[0] != "alice" {
		t.Errorf("accused = %v, want alice", got)
	}
	// And the node is kept, because that is what makes a donor manufacturing
	// signals visible later
	if features := judge.Features("alice"); len(features) != 1 || features[0].NodeID != "node-1" {
		t.Errorf("features = %+v", features)
	}
}

// A stale node still reporting on a revoked profile is not an accusation of
// anybody, and must not become one
func TestASignalForAnUnknownProfileAccusesNobody(t *testing.T) {
	e, judge, _ := setup(t)
	e.Observe(signal("p-ghost", fedpb.AbuseKind_ABUSE_KIND_MALWARE, 100), "node-1")
	if got := judge.Accused(); len(got) != 0 {
		t.Errorf("accused = %v out of thin air", got)
	}
}

// A little suspicion costs nodes, not access: most suspicion is wrong, and a
// throttle is recoverable where cutting somebody off is not
func TestMildSuspicionReducesRatherThanRevokes(t *testing.T) {
	e, _, alloc := setup(t)
	// Enough to leave the full band, not enough to quarantine
	for i := 0; i < 3; i++ {
		e.Observe(signal("p-alice", fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT, 1), "node-1")
	}
	changes := e.Tick()
	if len(changes) != 1 || changes[0].To != oracle.BandReduced {
		t.Fatalf("changes = %+v, want a move to reduced", changes)
	}
	if len(alloc.revoked) != 0 {
		t.Errorf("revoked %v for mild suspicion", alloc.revoked)
	}
	if got := e.Band("alice"); got != oracle.BandReduced {
		t.Errorf("band = %v", got)
	}
	if got := e.Band("alice").NodesFor(); got != 1 {
		t.Errorf("nodes = %d, want one", got)
	}
}

func TestQuarantineRevokes(t *testing.T) {
	e, _, alloc := setup(t)
	for i := 0; i < 4; i++ {
		e.Observe(signal("p-bob", fedpb.AbuseKind_ABUSE_KIND_MALWARE, 1), "node-1")
	}
	changes := e.Tick()
	if len(changes) != 1 || changes[0].To != oracle.BandQuarantine {
		t.Fatalf("changes = %+v, want quarantine", changes)
	}
	if len(alloc.revoked) != 1 || alloc.revoked[0] != "bob" {
		t.Errorf("revoked = %v", alloc.revoked)
	}
	if got := e.Band("bob").NodesFor(); got != 0 {
		t.Errorf("nodes = %d, want none", got)
	}
}

// A client sitting in the same band must not be revoked again every minute
func TestASteadyBandIsNotReapplied(t *testing.T) {
	e, _, alloc := setup(t)
	for i := 0; i < 4; i++ {
		e.Observe(signal("p-bob", fedpb.AbuseKind_ABUSE_KIND_MALWARE, 1), "node-1")
	}
	e.Tick()
	for i := 0; i < 5; i++ {
		if changes := e.Tick(); len(changes) != 0 {
			t.Fatalf("pass %d moved a steady client: %+v", i, changes)
		}
	}
	if len(alloc.revoked) != 1 {
		t.Errorf("revoked %d times, want once", len(alloc.revoked))
	}
}

// A clean user is never judged at all: the pass has no business scoring people
// nobody reported
func TestNobodyIsJudgedWithoutAnAccusation(t *testing.T) {
	e, _, alloc := setup(t)
	if changes := e.Tick(); len(changes) != 0 {
		t.Errorf("changes = %+v on a quiet fleet", changes)
	}
	if len(alloc.revoked) != 0 {
		t.Errorf("revoked %v on a quiet fleet", alloc.revoked)
	}
	if got := e.Band("never-seen"); got != oracle.BandFull {
		t.Errorf("an unreported user sits in %v", got)
	}
}

// The weight decays, so a bad week must not follow somebody around forever
func TestASuspicionFadesAndTheClientComesBack(t *testing.T) {
	judge := oracle.NewJudge(oracle.NewRulesScorer())
	alloc := &fakeAlloc{}
	e := New(judge, alloc, func(string) (string, bool) { return "alice", true })

	now := time.Now()
	judge.SetNow(func() time.Time { return now })
	for i := 0; i < 4; i++ {
		e.Observe(signal("p-alice", fedpb.AbuseKind_ABUSE_KIND_MALWARE, 1), "node-1")
	}
	if changes := e.Tick(); len(changes) != 1 || changes[0].To != oracle.BandQuarantine {
		t.Fatalf("changes = %+v", changes)
	}

	// Four half-lives later the same evidence is worth a sixteenth
	now = now.Add(28 * 24 * time.Hour)
	changes := e.Tick()
	if len(changes) != 1 || changes[0].To != oracle.BandFull {
		t.Fatalf("changes = %+v, want the client back after the evidence decayed", changes)
	}
}

// Сигнал про участника обязан доезжать до судьи. Через Observe он бы утонул на
// резолве профиля, и обвинение молча пропало бы, а человек так и ходил бы с
// нетронутым доверием
func TestSubjectSignalReachesTheJudge(t *testing.T) {
	enforcer, judge, _ := setup(t)
	enforcer.ObserveSubject(signal("user-1", fedpb.AbuseKind_ABUSE_KIND_NO_DEVICE_ID, 1), "")
	if got := judge.Judge("user-1"); got.Confidence >= oracle.StartingConfidence {
		t.Fatalf("доверие не шелохнулось: %d", got.Confidence)
	}
}

// А сигнал с ноды по-прежнему обязан резолвиться через профиль, иначе нода
// сможет обвинить кого угодно, назвав его как ей вздумается
func TestNodeSignalStillGoesThroughTheProfile(t *testing.T) {
	enforcer, judge, _ := setup(t)
	enforcer.Observe(signal("user-1", fedpb.AbuseKind_ABUSE_KIND_NO_DEVICE_ID, 1), "node-1")
	if got := judge.Judge("user-1"); got.Confidence != oracle.StartingConfidence {
		t.Fatalf("нода обвинила участника напрямую, минуя профиль: %d", got.Confidence)
	}
}
