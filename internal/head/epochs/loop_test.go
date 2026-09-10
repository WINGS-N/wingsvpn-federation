package epochs

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"wingsnet.org/federation/internal/head/payout"
)

// loopWithOneEpoch поднимает цикл, которому есть что закрыть прямо сейчас
func loopWithOneEpoch(t *testing.T) (*Loop, *fakeClock) {
	t.Helper()
	nodes := fakeNodes{
		list:      []NodeInfo{{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: true}},
		addresses: map[string]string{"1.2.3.4": "n1"},
	}
	collector := NewCollector(nodes, fakeClaimed{"n1": 50 * gib}, fakeConfirmed{"1.2.3.4": 50 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA}, newStore(), rate(), nil)

	start := time.Now().UTC().Add(-8 * 24 * time.Hour)
	clock := &fakeClock{end: start}
	loop := NewLoop(collector, clock, 7*24*time.Hour, nil)
	return loop, clock
}

type fakePublisher struct {
	published []uint64
	paid      []uint64
	fail      error
	payFail   error
}

func (f *fakePublisher) PayEveryone(_ context.Context, epoch *payout.Epoch) (int, error) {
	if f.payFail != nil {
		return 0, f.payFail
	}
	f.paid = append(f.paid, epoch.Number)
	return len(epoch.Leaves), nil
}

func (f *fakePublisher) Publish(_ context.Context, epoch *payout.Epoch) (string, error) {
	if f.fail != nil {
		return "", f.fail
	}
	f.published = append(f.published, epoch.Number)
	return "signature-" + strconv.FormatUint(epoch.Number, 10), nil
}

type fakeMarks struct{ marked map[uint64]string }

func (f *fakeMarks) MarkPublished(number uint64, _ time.Time, signature string) error {
	if f.marked == nil {
		f.marked = map[uint64]string{}
	}
	f.marked[number] = signature
	return nil
}

// Закрытая эпоха обязана уехать в цепочку: посчитанные начисления без корня это
// бумажка, склеймить по ней нельзя нихуя
func TestClosedEpochGoesToTheChain(t *testing.T) {
	loop, _ := loopWithOneEpoch(t)
	publisher := &fakePublisher{}
	marks := &fakeMarks{}
	loop.SetPublisher(publisher, marks)

	loop.Once()

	if len(publisher.published) != 1 {
		t.Fatalf("в цепочку уехало %d эпох", len(publisher.published))
	}
	if marks.marked[publisher.published[0]] == "" {
		t.Fatal("публикацию не записали, повтор пойдёт вторым разом")
	}
}

// Тупящий RPC не должен ронять учёт: эпоха закрыта и лежит в базе, публикацию
// повторит оператор
func TestAFailedPublishKeepsTheEpoch(t *testing.T) {
	loop, clock := loopWithOneEpoch(t)
	loop.SetPublisher(&fakePublisher{fail: errors.New("rpc сдох")}, &fakeMarks{})

	loop.Once()

	if end, _ := clock.LastPeriodEnd(); end.IsZero() {
		t.Fatal("период не закрыли из-за цепочки")
	}
}

// Донор ничего не подписывает и SOL не держит: закрытая эпоха обязана уехать в
// цепочку И тут же разойтись по кошелькам
func TestClosedEpochIsPaidOut(t *testing.T) {
	loop, _ := loopWithOneEpoch(t)
	publisher := &fakePublisher{}
	loop.SetPublisher(publisher, &fakeMarks{})

	loop.Once()

	if len(publisher.paid) != 1 {
		t.Fatalf("выплат прошло %d, а эпоха закрыта одна", len(publisher.paid))
	}
}

// Сдохшая выплата не должна ронять учёт: корень уже в цепочке, недоплату
// доберёт следующий заход
func TestAFailedPayoutKeepsTheEpochClosed(t *testing.T) {
	loop, clock := loopWithOneEpoch(t)
	loop.SetPublisher(&fakePublisher{payFail: errors.New("rpc сдох")}, &fakeMarks{})

	loop.Once()

	if end, _ := clock.LastPeriodEnd(); end.IsZero() {
		t.Fatal("период не закрыли из-за неудачной выплаты")
	}
}

type fakeRates struct {
	announced map[int64]uint64
	current   map[int64]uint64
}

func (f *fakeRates) AnnounceRate(periodStart time.Time, micro, _, _ uint64) error {
	if f.announced == nil {
		f.announced = map[int64]uint64{}
	}
	f.announced[periodStart.Unix()] = micro
	return nil
}

func (f *fakeRates) RateFor(periodStart time.Time) (uint64, bool, error) {
	micro, ok := f.current[periodStart.Unix()]
	return micro, ok, nil
}

type fakeTreasury struct {
	balance uint64
	err     error
}

func (f fakeTreasury) Balance(context.Context) (uint64, error) { return f.balance, f.err }

// Цена объявляется на следующий период сразу: донор должен видеть её ДО того,
// как повёз трафик
func TestRateIsAnnouncedForTheNextPeriod(t *testing.T) {
	loop, clock := loopWithOneEpoch(t)
	rates := &fakeRates{}
	loop.SetPublisher(&fakePublisher{}, &fakeMarks{})
	loop.SetRates(rates, fakeTreasury{balance: 600_000_000}, payout.RateBounds{Cap: 293, Floor: 10, SharePct: 60})

	loop.Once()

	end, _ := clock.LastPeriodEnd()
	if micro, ok := rates.announced[end.Unix()]; !ok || micro == 0 {
		t.Fatalf("на следующий период цену не объявили: %v", rates.announced)
	}
}

// Пустая казна означает нулевую ставку, а не долг: лишних обещаний не даём
// нахуй
func TestEmptyTreasuryAnnouncesNothingToPay(t *testing.T) {
	loop, clock := loopWithOneEpoch(t)
	rates := &fakeRates{}
	loop.SetPublisher(&fakePublisher{}, &fakeMarks{})
	loop.SetRates(rates, fakeTreasury{balance: 0}, payout.RateBounds{Cap: 293, Floor: 10, SharePct: 60})

	loop.Once()

	end, _ := clock.LastPeriodEnd()
	if micro := rates.announced[end.Unix()]; micro != 0 {
		t.Fatalf("на пустой казне объявили %d", micro)
	}
}

// Сдохшая цепочка не должна менять цену: старая остаётся в силе
func TestUnreadableTreasuryKeepsTheRate(t *testing.T) {
	loop, _ := loopWithOneEpoch(t)
	rates := &fakeRates{}
	loop.SetPublisher(&fakePublisher{}, &fakeMarks{})
	loop.SetRates(rates, fakeTreasury{err: errors.New("rpc сдох")}, payout.RateBounds{Cap: 293, Floor: 10, SharePct: 60})

	loop.Once()

	if len(rates.announced) != 0 {
		t.Fatalf("объявили цену вслепую: %v", rates.announced)
	}
}
