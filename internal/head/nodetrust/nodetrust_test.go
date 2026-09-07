package nodetrust

import (
	"testing"
	"time"
)

type fakeClaimed map[string]uint64

func (f fakeClaimed) NodeTraffic(time.Time) (map[string]uint64, error) { return f, nil }

type fakeConfirmed map[string]uint64

func (f fakeConfirmed) SignedByNode(time.Time) (map[string]uint64, error) { return f, nil }

func auditorAt(claimed fakeClaimed, confirmed fakeConfirmed, now time.Time) (*Auditor, *Judge) {
	judge := NewJudge()
	judge.now = func() time.Time { return now }
	a := NewAuditor(claimed, confirmed, nil, judge, nil)
	a.now = func() time.Time { return now }
	// Первый круг только запоминает: судят прирост, а не накопленный итог
	a.Once()
	return a, judge
}

// grow добавляет ноде прирост и подписи, как это выглядит на следующем круге
func grow(claimed fakeClaimed, confirmed fakeConfirmed, nodeID string, claim, signed uint64) {
	claimed[nodeID] += claim
	confirmed[nodeID] += signed
}

// Честная нода расходится с клиентами всегда: потери, ретрансмиты, оверхед. За
// это обвинять нельзя, иначе выебем весь флот разом
func TestAnHonestNodeIsLeftAlone(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claimed := fakeClaimed{"node-1": 0}
	confirmed := fakeConfirmed{"node-1": 0}
	a, judge := auditorAt(claimed, confirmed, now)
	grow(claimed, confirmed, "node-1", 1100<<20, 1000<<20)
	a.Once()
	if got := judge.Judge("node-1"); got.Trust != StartingTrust {
		t.Fatalf("честной ноде срезали доверие до %d", got.Trust)
	}
}

func TestOverclaimIsCaught(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claimed := fakeClaimed{"node-1": 0}
	confirmed := fakeConfirmed{"node-1": 0}
	a, judge := auditorAt(claimed, confirmed, now)
	grow(claimed, confirmed, "node-1", 10_000<<20, 1000<<20)
	a.Once()
	got := judge.Judge("node-1")
	if got.Trust >= StartingTrust {
		t.Fatalf("нода завысила вдесятеро и не огребла: %d", got.Trust)
	}
	if got.Reasons[ReasonOverclaim] == 0 {
		t.Fatal("причину не записали, донору нечего будет предъявить")
	}
}

// Одно расхождение не должно обнулять выплату: у донора мог быть сбойный день,
// а мы ему месяц работы спишем
func TestOneClaimDoesNotBenchANode(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claimed := fakeClaimed{"node-1": 0}
	confirmed := fakeConfirmed{"node-1": 0}
	a, judge := auditorAt(claimed, confirmed, now)
	grow(claimed, confirmed, "node-1", 10_000<<20, 1000<<20)
	a.Once()
	if judge.Judge("node-1").Unpaid() {
		t.Fatal("ноде обнулили выплату с одного срабатывания")
	}
}

// А вот упорство должно топить
func TestRepeatedOverclaimBenchesTheNode(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claimed := fakeClaimed{"node-1": 0}
	confirmed := fakeConfirmed{"node-1": 0}
	a, judge := auditorAt(claimed, confirmed, now)
	for i := 0; i < 4; i++ {
		grow(claimed, confirmed, "node-1", 10_000<<20, 500<<20)
		a.Once()
	}
	if got := judge.Judge("node-1"); !got.Unpaid() {
		t.Fatalf("нода врёт четвёртый раз подряд и всё ещё при деньгах: %d", got.Trust)
	}
}

// Мелкий трафик сверять бессмысленно, проценты на нём скачут как хотят
func TestSmallTrafficIsNotAudited(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claimed := fakeClaimed{"node-1": 0}
	confirmed := fakeConfirmed{"node-1": 0}
	a, judge := auditorAt(claimed, confirmed, now)
	grow(claimed, confirmed, "node-1", 8<<20, 0)
	a.Once()
	if judge.Judge("node-1").Trust != StartingTrust {
		t.Fatal("обвинили за восемь мегабайт")
	}
}

func TestOldClaimsFadeAway(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	judge := NewJudge()
	judge.now = func() time.Time { return now }
	judge.Observe(Claim{NodeID: "node-1", Reason: ReasonOverclaim, Magnitude: 20, At: now})
	fresh := judge.Judge("node-1").Trust

	judge.now = func() time.Time { return now.Add(28 * 24 * time.Hour) }
	if later := judge.Judge("node-1").Trust; later <= fresh {
		t.Fatalf("через месяц вина не полегчала: было %d, стало %d", fresh, later)
	}
}

func TestAccusedIsSortedWorstFirst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	judge := NewJudge()
	judge.now = func() time.Time { return now }
	judge.Observe(Claim{NodeID: "good", Reason: ReasonFlapping, Magnitude: 1, At: now})
	judge.Observe(Claim{NodeID: "bad", Reason: ReasonOverclaim, Magnitude: 30, At: now})

	got := judge.Accused()
	if len(got) != 2 || got[0].NodeID != "bad" {
		t.Fatalf("худшая нода не первая: %+v", got)
	}
}

// После рестарта башки память пуста, и весь накопленный итог выглядел бы как
// свежее враньё. Обвинить весь флот разом - это не аудит, это погром
func TestTheFirstPassAccusesNobody(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	judge := NewJudge()
	judge.now = func() time.Time { return now }
	a := NewAuditor(
		fakeClaimed{"node-1": 900_000 << 20},
		fakeConfirmed{},
		nil, judge, nil,
	)
	a.now = func() time.Time { return now }
	a.Once()
	if got := judge.Judge("node-1"); got.Trust != StartingTrust {
		t.Fatalf("первый круг после старта уже кого-то обвинил: %d", got.Trust)
	}
}

type fakeResolver map[string]string

func (f fakeResolver) NodeByAddress(address string) (string, bool) {
	id, ok := f[address]
	return id, ok
}

// Клиент подписывает адрес, а счётчики лежат под идентификатором. Без перевода
// не сойдётся ни один ключ, и честная нода будет выглядеть как нода без единой
// расписки
func TestAddressesAreResolvedToNodes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claimed := fakeClaimed{"node-1": 0}
	confirmed := fakeConfirmed{"1.2.3.4": 0}
	judge := NewJudge()
	judge.now = func() time.Time { return now }
	a := NewAuditor(claimed, confirmed, fakeResolver{"1.2.3.4": "node-1"}, judge, nil)
	a.now = func() time.Time { return now }
	a.Once()

	claimed["node-1"] += 1100 << 20
	confirmed["1.2.3.4"] += 1000 << 20
	a.Once()
	if got := judge.Judge("node-1"); got.Trust != StartingTrust {
		t.Fatalf("честную ноду обвинили из-за неразрешённого адреса: %d", got.Trust)
	}
}

// Между порогами платим пропорционально, а не рубим сплеча
func TestPayoutFadesInsteadOfSnapping(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	judge := NewJudge()
	judge.now = func() time.Time { return now }

	if got := judge.Judge("clean").PayoutFactor(); got != 1 {
		t.Fatalf("чистой ноде срезали выплату: %.2f", got)
	}
	judge.Observe(Claim{NodeID: "shaky", Reason: ReasonOverclaim, Magnitude: 2, At: now})
	judge.Observe(Claim{NodeID: "shaky", Reason: ReasonFlapping, Magnitude: 2, At: now})
	factor := judge.Judge("shaky").PayoutFactor()
	if factor <= 0 || factor >= 1 {
		t.Fatalf("выплата не смягчилась, а рубанулась: %.2f", factor)
	}
	for i := 0; i < 4; i++ {
		judge.Observe(Claim{NodeID: "liar", Reason: ReasonOverclaim, Magnitude: 20, At: now})
	}
	if got := judge.Judge("liar").PayoutFactor(); got != 0 {
		t.Fatalf("врущей ноде всё ещё платят: %.2f", got)
	}
}
