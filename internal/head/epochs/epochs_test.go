package epochs

import (
	"testing"
	"time"

	"wingsnet.org/federation/internal/head/payout"
)

const gib = uint64(1) << 30

var (
	walletA = "So11111111111111111111111111111111111111112"
	walletB = "SysvarRent111111111111111111111111111111111"
)

type fakeNodes struct {
	list      []NodeInfo
	addresses map[string]string
}

func (f fakeNodes) ForPayout(time.Time) []NodeInfo { return f.list }

func (f fakeNodes) NodeByAddress(address string) (string, bool) {
	id, ok := f.addresses[address]
	return id, ok
}

type fakeClaimed map[string]uint64

func (f fakeClaimed) NodeTraffic(time.Time) (map[string]uint64, error) {
	return map[string]uint64(f), nil
}

type fakeConfirmed map[string]uint64

func (f fakeConfirmed) SignedByNodeBetween(time.Time, time.Time) (map[string]uint64, error) {
	return map[string]uint64(f), nil
}

type fullTrust struct{}

func (fullTrust) FactorBps(string) uint32 { return 10_000 }

type fakeAddresses map[string]string

func (f fakeAddresses) Address(donorID string) (string, bool) {
	addr, ok := f[donorID]
	return addr, ok
}

type memStore struct {
	last      uint64
	saved     *payout.Epoch
	donors    map[string]string
	baselines map[string]uint64
}

func newStore() *memStore {
	return &memStore{baselines: map[string]uint64{}}
}

func (m *memStore) Last() (uint64, error) { return m.last, nil }

func (m *memStore) Next() (uint64, error) {
	if m.saved == nil {
		return 0, nil
	}
	return m.last + 1, nil
}

func (m *memStore) Save(epoch *payout.Epoch, donorByAddress map[string]string) error {
	m.saved, m.donors, m.last = epoch, donorByAddress, epoch.Number
	return nil
}

func (m *memStore) Baselines() (map[string]uint64, error) { return m.baselines, nil }

func (m *memStore) SaveBaselines(next map[string]uint64) error {
	m.baselines = next
	return nil
}

func window() (time.Time, time.Time) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return start, start.Add(7 * 24 * time.Hour)
}

func rate() payout.Rate { return payout.Rate{MicroPerGiB: 10_000} }

// Период считается ПРИРОСТОМ счётчика, иначе на второй эпохе донор получит ещё
// раз за всё, что уже оплачено
func TestSecondEpochPaysOnlyTheGrowth(t *testing.T) {
	start, end := window()
	nodes := fakeNodes{
		list:      []NodeInfo{{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: true}},
		addresses: map[string]string{"1.2.3.4": "n1"},
	}
	store := newStore()
	collector := NewCollector(nodes, fakeClaimed{"n1": 50 * gib}, fakeConfirmed{"1.2.3.4": 50 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA}, store, rate(), nil)

	first, err := collector.Close(start, end)
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != payout.Micro(500_000) {
		t.Fatalf("первая эпоха насчитала %s, а за 50 GiB причитается 0.5 USDT", first.Total.FormatUSDT())
	}

	// Ко второй эпохе нода намолотила ещё 20 GiB
	collector.claimed = fakeClaimed{"n1": 70 * gib}
	collector.confirmed = fakeConfirmed{"1.2.3.4": 70 * gib}
	second, err := collector.Close(end, end.Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Total != payout.Micro(200_000) {
		t.Fatalf("вторая эпоха насчитала %s, а прирост был 20 GiB", second.Total.FormatUSDT())
	}
	// Нумерация идёт с нуля: программа в цепочке принимает ровно тот номер,
	// которого ждёт, а заводится она с нулевого
	if first.Number != 0 {
		t.Fatalf("номер первой эпохи %d, а цепочка ждёт нулевую", first.Number)
	}
	if second.Number != 1 {
		t.Fatalf("номер эпохи %d, а она вторая после нулевой", second.Number)
	}
}

// Ноду переставили с нуля - весь её текущий итог и есть прирост, а не
// отрицательная величина
func TestCounterResetDoesNotBreakTheEpoch(t *testing.T) {
	start, end := window()
	nodes := fakeNodes{
		list:      []NodeInfo{{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: true}},
		addresses: map[string]string{"1.2.3.4": "n1"},
	}
	store := newStore()
	store.baselines = map[string]uint64{"n1": 900 * gib}
	collector := NewCollector(nodes, fakeClaimed{"n1": 3 * gib}, fakeConfirmed{"1.2.3.4": 10 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA}, store, rate(), nil)

	epoch, err := collector.Close(start, end)
	if err != nil {
		t.Fatal(err)
	}
	if epoch.Total != payout.Micro(30_000) {
		t.Fatalf("после сброса счётчика начислено %s, а прирост 3 GiB", epoch.Total.FormatUSDT())
	}
}

// Клиент подписывает АДРЕС, а не наш внутренний id: без перевода расписок нет
// ни у одной ноды, и весь флот остаётся без денег
func TestReceiptsAreResolvedFromAddressToNode(t *testing.T) {
	start, end := window()
	nodes := fakeNodes{
		list: []NodeInfo{{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: true}},
		// У ноды два адреса, и оба её
		addresses: map[string]string{"1.2.3.4": "n1", "2001:db8::1": "n1"},
	}
	store := newStore()
	collector := NewCollector(nodes, fakeClaimed{"n1": 100 * gib},
		fakeConfirmed{"1.2.3.4": 6 * gib, "2001:db8::1": 4 * gib, "9.9.9.9": 500 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA}, store, rate(), nil)

	epoch, err := collector.Close(start, end)
	if err != nil {
		t.Fatal(err)
	}
	// 6+4 GiB своих; чужой адрес 9.9.9.9 не принадлежит никому и в счёт не идёт
	if epoch.Total != payout.Micro(100_000) {
		t.Fatalf("начислено %s, а расписок на 10 GiB", epoch.Total.FormatUSDT())
	}
}

// Донор без кошелька не ломает эпоху остальным, но и база его ноды сдвигается,
// иначе при появлении кошелька он получит за всё прошлое разом
func TestDonorWithoutWalletDoesNotBlockTheEpoch(t *testing.T) {
	start, end := window()
	nodes := fakeNodes{
		list: []NodeInfo{
			{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: true},
			{NodeID: "n2", DonorID: "no-wallet", ProbeConfirmed: true},
		},
		addresses: map[string]string{"1.2.3.4": "n1", "5.6.7.8": "n2"},
	}
	store := newStore()
	collector := NewCollector(nodes, fakeClaimed{"n1": 10 * gib, "n2": 80 * gib},
		fakeConfirmed{"1.2.3.4": 10 * gib, "5.6.7.8": 80 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA}, store, rate(), nil)

	epoch, err := collector.Close(start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(epoch.Leaves) != 1 || epoch.Leaves[0].Address != walletA {
		t.Fatalf("в эпоху попал не тот, у кого есть кошелёк: %+v", epoch.Leaves)
	}
	if store.baselines["n2"] != 80*gib {
		t.Fatal("база безкошелькового донора не сдвинулась, он получит за это дважды")
	}
}

// Период, в котором платить некому, обязан двигать базу - иначе следующий
// оплатит и его тоже
func TestEmptyPeriodStillMovesTheBaseline(t *testing.T) {
	start, end := window()
	nodes := fakeNodes{
		list:      []NodeInfo{{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: false}},
		addresses: map[string]string{"1.2.3.4": "n1"},
	}
	store := newStore()
	collector := NewCollector(nodes, fakeClaimed{"n1": 40 * gib}, fakeConfirmed{"1.2.3.4": 40 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA}, store, rate(), nil)

	if _, err := collector.Close(start, end); err != ErrNothingToPay {
		t.Fatalf("неподтверждённая нода дала эпоху: %v", err)
	}
	if store.baselines["n1"] != 40*gib {
		t.Fatal("пустой период не сдвинул базу")
	}
	if store.last != 0 {
		t.Fatal("номер эпохи потрачен на период, в котором никому не платят")
	}
}

// Два донора - два листа, и каждый со своим кошельком
func TestEachDonorGetsTheirOwnLeaf(t *testing.T) {
	start, end := window()
	nodes := fakeNodes{
		list: []NodeInfo{
			{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: true},
			{NodeID: "n2", DonorID: "admin-2", ProbeConfirmed: true},
		},
		addresses: map[string]string{"1.2.3.4": "n1", "5.6.7.8": "n2"},
	}
	store := newStore()
	collector := NewCollector(nodes, fakeClaimed{"n1": 10 * gib, "n2": 30 * gib},
		fakeConfirmed{"1.2.3.4": 10 * gib, "5.6.7.8": 30 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA, "admin-2": walletB}, store, rate(), nil)

	epoch, err := collector.Close(start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(epoch.Leaves) != 2 {
		t.Fatalf("листьев %d, а доноров двое", len(epoch.Leaves))
	}
	if store.donors[walletA] != "admin-1" || store.donors[walletB] != "admin-2" {
		t.Fatalf("кошельки разъехались с донорами: %+v", store.donors)
	}
	// Пруф каждого обязан сойтись, иначе клеймить бесполезно
	for _, leaf := range epoch.Leaves {
		proof, err := epoch.Proof(leaf.Address)
		if err != nil {
			t.Fatal(err)
		}
		index, ok := epoch.IndexOf(leaf.Address)
		if !ok {
			t.Fatalf("лист %s потерялся в дереве", leaf.Address)
		}
		hash, err := payout.LeafHash(epoch.Number, index, leaf)
		if err != nil {
			t.Fatal(err)
		}
		if !payout.VerifyProof(epoch.Root, hash, proof) {
			t.Fatalf("пруф для %s не сошёлся", leaf.Address)
		}
	}
}

// fakeClock - отметка о последнем закрытом периоде
type fakeClock struct {
	end time.Time
}

func (f *fakeClock) LastPeriodEnd() (time.Time, error) { return f.end, nil }

func (f *fakeClock) SetPeriodEnd(t time.Time) error {
	f.end = t
	return nil
}

func collectorFor(store *memStore) *Collector {
	nodes := fakeNodes{
		list:      []NodeInfo{{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: true}},
		addresses: map[string]string{"1.2.3.4": "n1"},
	}
	return NewCollector(nodes, fakeClaimed{"n1": 10 * gib}, fakeConfirmed{"1.2.3.4": 10 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA}, store, rate(), nil)
}

// Первый запуск не должен закрывать период задним числом: счётчики за прошлое
// уже сложены, и такая эпоха вышла бы бесконечной
func TestFirstRunOnlyPlantsTheMark(t *testing.T) {
	store := newStore()
	clock := &fakeClock{}
	loop := NewLoop(collectorFor(store), clock, time.Hour, nil)
	loop.now = func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) }

	loop.Once()
	if store.saved != nil {
		t.Fatal("первый запуск закрыл эпоху вместо того, чтобы просто отметиться")
	}
	if clock.end.IsZero() {
		t.Fatal("отметка о начале отсчёта не поставлена")
	}
}

// Пока период не кончился, эпоха не закрывается
func TestPeriodIsNotClosedEarly(t *testing.T) {
	store := newStore()
	start := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{end: start}
	loop := NewLoop(collectorFor(store), clock, 24*time.Hour, nil)
	loop.now = func() time.Time { return start.Add(6 * time.Hour) }

	loop.Once()
	if store.saved != nil {
		t.Fatal("эпоха закрылась раньше срока")
	}
	if !clock.end.Equal(start) {
		t.Fatal("отметка сдвинулась, хотя период не кончился")
	}
}

// Кончился - закрываем и двигаем отметку ровно на длину периода, а не на "сейчас"
func TestClosedPeriodAdvancesByExactlyOnePeriod(t *testing.T) {
	store := newStore()
	start := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{end: start}
	loop := NewLoop(collectorFor(store), clock, 24*time.Hour, nil)
	// Башка простояла три дня: закрываем ближайший период, остальные догонятся
	// следующими тиками, и ни один не потеряется
	loop.now = func() time.Time { return start.Add(72 * time.Hour) }

	loop.Once()
	if store.saved == nil {
		t.Fatal("период кончился, а эпоха не закрыта")
	}
	if !clock.end.Equal(start.Add(24 * time.Hour)) {
		t.Fatalf("отметка уехала на %s, а период суточный", clock.end.Sub(start))
	}
}

// Период, за который платить некому, всё равно закрывается: иначе он приклеится
// к следующему и оплатится дважды
func TestEmptyPeriodStillAdvancesTheMark(t *testing.T) {
	store := newStore()
	start := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{end: start}
	nodes := fakeNodes{
		list:      []NodeInfo{{NodeID: "n1", DonorID: "admin-1", ProbeConfirmed: false}},
		addresses: map[string]string{"1.2.3.4": "n1"},
	}
	collector := NewCollector(nodes, fakeClaimed{"n1": 10 * gib}, fakeConfirmed{"1.2.3.4": 10 * gib},
		fullTrust{}, fakeAddresses{"admin-1": walletA}, store, rate(), nil)
	loop := NewLoop(collector, clock, 24*time.Hour, nil)
	loop.now = func() time.Time { return start.Add(48 * time.Hour) }

	loop.Once()
	if !clock.end.Equal(start.Add(24 * time.Hour)) {
		t.Fatal("пустой период не закрылся и приклеится к следующему")
	}
}
