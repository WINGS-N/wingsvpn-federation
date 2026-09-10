package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

func addNode(t *testing.T, r *Registry, id, fingerprint string) *Node {
	t.Helper()
	n := &Node{ID: id, Fingerprint: fingerprint, Secret: "s-" + id, DeclaredBudgetBytes: 1 << 30}
	r.Add(n)
	return n
}

// Usage is derived from cumulative counters so a dropped sample costs nothing
func TestApplySampleBillsTheDelta(t *testing.T) {
	r := New()
	addNode(t, r, "n1", "fp1")

	if _, err := r.ApplySample("n1", "boot-a", 1000, 2000, 0); err != nil {
		t.Fatal(err)
	}
	// First sample only establishes the baseline; nothing has been observed
	// flowing yet, so nothing may be billed
	n, _ := r.Get("n1")
	if n.UsedBytes != 0 {
		t.Errorf("first sample billed %d bytes, want 0", n.UsedBytes)
	}

	billed, err := r.ApplySample("n1", "boot-a", 1500, 2500, 0)
	if err != nil {
		t.Fatal(err)
	}
	if billed != 1000 {
		t.Errorf("billed = %d, want 1000", billed)
	}
	if n, _ = r.Get("n1"); n.UsedBytes != 1000 {
		t.Errorf("used = %d, want 1000", n.UsedBytes)
	}
}

// A restart resets the node's counters to zero. Without re-baselining, the next
// sample would look like a huge negative delta or, worse, silently hand the
// donor back the traffic already spent
func TestRestartDoesNotRefundSpentTraffic(t *testing.T) {
	r := New()
	addNode(t, r, "n1", "fp1")
	_, _ = r.ApplySample("n1", "boot-a", 0, 0, 0)
	_, _ = r.ApplySample("n1", "boot-a", 5000, 5000, 0)

	before, _ := r.Get("n1")
	spent := before.UsedBytes
	if spent != 10000 {
		t.Fatalf("setup: used = %d, want 10000", spent)
	}

	// Same node, new boot: counters start over
	billed, err := r.ApplySample("n1", "boot-b", 10, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if billed != 0 {
		t.Errorf("restart billed %d bytes, want 0", billed)
	}
	after, _ := r.Get("n1")
	if after.UsedBytes != spent {
		t.Errorf("used = %d after restart, want it unchanged at %d", after.UsedBytes, spent)
	}

	// And accounting continues from the new baseline
	billed, _ = r.ApplySample("n1", "boot-b", 110, 10, 0)
	if billed != 100 {
		t.Errorf("post-restart billed = %d, want 100", billed)
	}
}

// A counter that moves backwards without a boot change is still a reset as far
// as billing is concerned; it must never underflow into a giant delta
func TestBackwardCounterIsNotBilled(t *testing.T) {
	r := New()
	addNode(t, r, "n1", "fp1")
	_, _ = r.ApplySample("n1", "boot-a", 9000, 9000, 0)
	billed, err := r.ApplySample("n1", "boot-a", 5, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if billed != 0 {
		t.Errorf("backward counter billed %d, want 0", billed)
	}
}

// Re-running the installer must not fork a second identity that keeps its own
// budget, so an enrollment with a known fingerprint replaces the old row
func TestReenrollmentReplacesTheSameMachine(t *testing.T) {
	r := New()
	addNode(t, r, "old", "fp1")
	addNode(t, r, "new", "fp1")
	addNode(t, r, "other", "fp2")

	if _, err := r.Get("old"); err == nil {
		t.Error("the previous enrollment of the same machine survived")
	}
	if _, err := r.Get("new"); err != nil {
		t.Error("the new enrollment is missing")
	}
	if _, err := r.Get("other"); err != nil {
		t.Error("an unrelated node was dropped")
	}
}

func TestAuthenticateRejectsWrongSecret(t *testing.T) {
	r := New()
	addNode(t, r, "n1", "fp1")
	if _, err := r.Authenticate("n1", "s-n1"); err != nil {
		t.Errorf("valid secret rejected: %v", err)
	}
	if _, err := r.Authenticate("n1", "wrong"); err == nil {
		t.Error("wrong secret accepted")
	}
	if _, err := r.Authenticate("n1", ""); err == nil {
		t.Error("empty secret accepted")
	}
	if _, err := r.Authenticate("ghost", "s"); err == nil {
		t.Error("unknown node accepted")
	}
}

// A node that stopped reporting must not be handed out, whatever its score
func TestOnlineWindow(t *testing.T) {
	now := time.Now()
	n := &Node{LastSeen: now.Add(-3 * time.Second)}
	if !n.Online(now, 15*time.Second) {
		t.Error("a node seen 3s ago should count as online")
	}
	if n.Online(now, time.Second) {
		t.Error("a node seen 3s ago should be stale within a 1s window")
	}
	fresh := &Node{}
	if fresh.Online(now, time.Minute) {
		t.Error("a node that never reported should never count as online")
	}
}

func TestSetState(t *testing.T) {
	r := New()
	addNode(t, r, "n1", "fp1")
	if err := r.SetState("n1", fedpb.RotationState_ROTATION_STATE_DRAINING, "budget"); err != nil {
		t.Fatal(err)
	}
	n, _ := r.Get("n1")
	if n.State != fedpb.RotationState_ROTATION_STATE_DRAINING || n.Reason != "budget" {
		t.Errorf("state = %v reason = %q", n.State, n.Reason)
	}
	if err := r.SetState("ghost", fedpb.RotationState_ROTATION_STATE_PARKED, ""); err != ErrUnknownNode {
		t.Errorf("err = %v, want ErrUnknownNode", err)
	}
}

// A head restart must not de-enroll the fleet: agents keep valid secrets, and a
// head that forgot them would reject every one at once
func TestRegistrySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")

	first, err := Open(NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	first.Add(&Node{ID: "n1", Fingerprint: "fp1", Secret: "sec", DonorID: "d1", DeclaredBudgetBytes: 1 << 30})
	_, _ = first.ApplySample("n1", "boot-a", 0, 0, 0)
	if _, err := first.ApplySample("n1", "boot-a", 4000, 1000, 0); err != nil {
		t.Fatal(err)
	}

	// A brand new head process reading the same file
	second, err := Open(NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	node, err := second.Authenticate("n1", "sec")
	if err != nil {
		t.Fatalf("a node with a valid secret was rejected after restart: %v", err)
	}
	if node.DonorID != "d1" {
		t.Errorf("donor = %q, want d1", node.DonorID)
	}
	// Spent traffic must not come back, or a restart refunds every donor
	if node.UsedBytes != 5000 {
		t.Errorf("used = %d after restart, want 5000", node.UsedBytes)
	}
}

// A head killed mid-write must leave the previous registry readable rather than
// a truncated file that de-enrolls everybody
func TestStoreWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	store := NewFileStore(path)
	if err := store.Save([]*Node{{ID: "n1", Secret: "s"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temp file was left behind: %s", e.Name())
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600: the file holds every node secret", perm)
	}
}

func TestLoadMissingFileIsEmptyFleet(t *testing.T) {
	r, err := Open(NewFileStore(filepath.Join(t.TempDir(), "absent.json")))
	if err != nil {
		t.Fatalf("a first run must not fail: %v", err)
	}
	if len(r.List()) != 0 {
		t.Error("a fresh head started with nodes")
	}
}

func atTime(r *Registry, t time.Time) { r.now = func() time.Time { return t } }

// A pledge is monthly. Without the roll the first node to burn its budget stays
// parked forever, which from the outside is indistinguishable from a dead fleet
func TestBudgetResetsWhenTheMonthTurns(t *testing.T) {
	r := New()
	march := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	atTime(r, march)
	r.Add(&Node{ID: "n1", Secret: "s", DeclaredBudgetBytes: 1000})
	if _, err := r.ApplySample("n1", "b", 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplySample("n1", "b", 300, 200, 0); err != nil {
		t.Fatal(err)
	}
	n, _ := r.Get("n1")
	if n.UsedBytes != 500 {
		t.Fatalf("used = %d, want 500", n.UsedBytes)
	}

	atTime(r, march.AddDate(0, 0, 5))
	if rolled := r.RollPeriods(); len(rolled) != 0 {
		t.Errorf("rolled inside the same month: %v", rolled)
	}
	if n, _ := r.Get("n1"); n.UsedBytes != 500 {
		t.Errorf("used = %d mid-month, want it kept", n.UsedBytes)
	}

	atTime(r, time.Date(2026, 4, 1, 0, 0, 1, 0, time.UTC))
	if rolled := r.RollPeriods(); len(rolled) != 1 || rolled[0] != "n1" {
		t.Fatalf("rolled = %v, want n1", rolled)
	}
	if n, _ := r.Get("n1"); n.UsedBytes != 0 {
		t.Errorf("used = %d after the month turned, want 0", n.UsedBytes)
	}
}

// A restart must not hand the donor back a month they already spent
func TestPeriodSurvivesAReload(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir + "/reg.json")
	r, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	march := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	atTime(r, march)
	r.Add(&Node{ID: "n1", Secret: "s", DeclaredBudgetBytes: 1000})
	if _, err := r.ApplySample("n1", "b", 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplySample("n1", "b", 400, 0, 0); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Open(NewFileStore(dir + "/reg.json"))
	if err != nil {
		t.Fatal(err)
	}
	atTime(reloaded, march.AddDate(0, 0, 1))
	n, err := reloaded.Get("n1")
	if err != nil {
		t.Fatal(err)
	}
	if n.UsedBytes != 400 {
		t.Errorf("used = %d after reload, want 400", n.UsedBytes)
	}
	if !n.PeriodStart.Equal(monthStart(march)) {
		t.Errorf("period start = %v, want the march anchor", n.PeriodStart)
	}
	if rolled := reloaded.RollPeriods(); len(rolled) != 0 {
		t.Errorf("a reload invented a new month: %v", rolled)
	}
}

// One busy second is not a reason to move somebody's traffic elsewhere
func TestHeartbeatSmoothsCPU(t *testing.T) {
	r := New()
	r.Add(&Node{ID: "n1", Secret: "s"})
	if err := r.ApplyHeartbeat("n1", 10, 100, "running", "ready"); err != nil {
		t.Fatal(err)
	}
	n, _ := r.Get("n1")
	if n.Health.CPUPct != 10 {
		t.Fatalf("first sample = %v, want it taken as is", n.Health.CPUPct)
	}
	if err := r.ApplyHeartbeat("n1", 100, 105, "running", "ready"); err != nil {
		t.Fatal(err)
	}
	n, _ = r.Get("n1")
	if n.Health.CPUPct >= 100 || n.Health.CPUPct <= 10 {
		t.Errorf("cpu = %v, want a spike smoothed between the two", n.Health.CPUPct)
	}
	if n.Health.XrayState != "running" {
		t.Errorf("xray state = %q", n.Health.XrayState)
	}
	if err := r.ApplyHeartbeat("nope", 1, 1, "", ""); err == nil {
		t.Error("a heartbeat for an unknown node was accepted")
	}
}

// Бюджет меняется на живой ноде. Пока этого не было, поднять лимит можно было
// только перезачислением - с потерей личности ноды и уже посчитанного трафика.
func TestBudgetChangesWithoutReEnrolling(t *testing.T) {
	r := New()
	r.Add(&Node{ID: "n1", DeclaredBudgetBytes: 100, UsedBytes: 40})

	if err := r.SetBudget("n1", 500); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get("n1")
	if err != nil {
		t.Fatal(err)
	}
	if got.DeclaredBudgetBytes != 500 {
		t.Errorf("бюджет = %d, want 500", got.DeclaredBudgetBytes)
	}
	if got.UsedBytes != 40 {
		t.Errorf("потраченное сбросилось: %d", got.UsedBytes)
	}
}

// Ноль запрещён: такую ноду нельзя выдать никому, и молчаливое согласие
// выглядело бы как нода, которая просто перестала работать.
func TestBudgetRefusesZero(t *testing.T) {
	r := New()
	r.Add(&Node{ID: "n1", DeclaredBudgetBytes: 100})
	if err := r.SetBudget("n1", 0); err == nil {
		t.Fatal("нулевой бюджет принят")
	}
	if err := r.SetBudget("missing", 10); err == nil {
		t.Fatal("бюджет выставлен несуществующей ноде")
	}
}

// Урезать ниже потраченного можно намеренно: донор говорит "хватит", а ротация
// сама сольёт ноду и припаркует - отдельный выключатель не нужен.
func TestBudgetMayDropBelowWhatWasSpent(t *testing.T) {
	r := New()
	r.Add(&Node{ID: "n1", DeclaredBudgetBytes: 1000, UsedBytes: 900})
	if err := r.SetBudget("n1", 500); err != nil {
		t.Fatalf("урезание отвергнуто: %v", err)
	}
	got, _ := r.Get("n1")
	if got.DeclaredBudgetBytes != 500 {
		t.Errorf("бюджет = %d, want 500", got.DeclaredBudgetBytes)
	}
}

// Dest уходит в каждую выданную ссылку как SNI. Он обязан держаться за нодой:
// пересчёт по пулу меняет ответ при любом изменении пула и убивает все ссылки,
// которые люди уже добавили в приложение.
func TestDestSticksToTheNode(t *testing.T) {
	r := New()
	r.Add(&Node{ID: "n1"})

	if err := r.SetDest("n1", "ok.ru:443"); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get("n1")
	if err != nil {
		t.Fatal(err)
	}
	if got.RealityDest != "ok.ru:443" {
		t.Fatalf("dest = %q", got.RealityDest)
	}

	// Пустой не затирает закреплённый: "нечего сказать" не равно "сотри"
	if err := r.SetDest("n1", ""); err != nil {
		t.Fatal(err)
	}
	if again, _ := r.Get("n1"); again.RealityDest != "ok.ru:443" {
		t.Errorf("пустое значение стёрло dest: %q", again.RealityDest)
	}
}

// Трафик зондов донору всё равно считается, но виден отдельной цифрой
func TestApplySampleTracksProbeBytesApart(t *testing.T) {
	r := New()
	addNode(t, r, "n1", "fp1")
	january := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	atTime(r, january)

	if _, err := r.ApplySample("n1", "boot-a", 1000, 1000, 200); err != nil {
		t.Fatal(err)
	}
	billed, err := r.ApplySample("n1", "boot-a", 3000, 3000, 700)
	if err != nil {
		t.Fatal(err)
	}
	// Из 4000 байт прироста 500 нагнали зонды, и в счёт донору они не идут
	if billed != 3500 {
		t.Fatalf("billed = %d, want 3500", billed)
	}
	n, _ := r.Get("n1")
	if n.UsedBytes != 3500 {
		t.Fatalf("used = %d, want 3500", n.UsedBytes)
	}
	if n.ProbeBytes != 500 {
		t.Fatalf("probe = %d, want 500", n.ProbeBytes)
	}

	// Нода перезагрузилась: счётчики поехали с нуля, и дельту брать нельзя
	if _, err := r.ApplySample("n1", "boot-b", 10, 10, 5); err != nil {
		t.Fatal(err)
	}
	n, _ = r.Get("n1")
	if n.ProbeBytes != 500 {
		t.Fatalf("ребут не должен добавлять зондам: probe = %d, want 500", n.ProbeBytes)
	}

	// Новый месяц обнуляет обе цифры, иначе бюджет живёт вечно
	atTime(r, time.Date(2026, 2, 1, 0, 5, 0, 0, time.UTC))
	if _, err := r.ApplySample("n1", "boot-b", 20, 20, 10); err != nil {
		t.Fatal(err)
	}
	n, _ = r.Get("n1")
	// Прирост 20 байт, из них 5 зондовых: донору в счёт идут 15
	if n.ProbeBytes != 5 || n.UsedBytes != 15 {
		t.Fatalf("после смены месяца probe = %d, used = %d", n.ProbeBytes, n.UsedBytes)
	}
}

// Замеры зондов гоняем мы сами, и бюджет донора они жрать не должны
func TestProbeTrafficIsNotBilledToTheDonor(t *testing.T) {
	reg, err := Open(NewFileStore(filepath.Join(t.TempDir(), "reg.json")))
	if err != nil {
		t.Fatal(err)
	}
	reg.Add(&Node{ID: "n1", DonorID: "admin-1", DeclaredBudgetBytes: 500 << 30})

	// Первый сэмпл только задаёт базу
	if _, err := reg.ApplySample("n1", "boot-1", 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	// Прошло 10 GiB, из них 8 GiB нагнали зонды
	billed, err := reg.ApplySample("n1", "boot-1", 6<<30, 4<<30, 8<<30)
	if err != nil {
		t.Fatal(err)
	}
	if billed != 2<<30 {
		t.Fatalf("в счёт пошло %d байт, а людям принадлежит 2 GiB", billed)
	}
	node, err := reg.Get("n1")
	if err != nil {
		t.Fatal(err)
	}
	if node.UsedBytes != 2<<30 {
		t.Fatalf("бюджет съеден на %d байт вместо 2 GiB", node.UsedBytes)
	}
	if node.ProbeBytes != 8<<30 {
		t.Fatalf("замеры зондов посчитаны как %d вместо 8 GiB", node.ProbeBytes)
	}
}

// Круг, в котором ехали одни замеры, бюджет не трогает вообще
func TestProbeOnlyRoundBillsNothing(t *testing.T) {
	reg, err := Open(NewFileStore(filepath.Join(t.TempDir(), "reg.json")))
	if err != nil {
		t.Fatal(err)
	}
	reg.Add(&Node{ID: "n1", DonorID: "admin-1", DeclaredBudgetBytes: 500 << 30})
	if _, err := reg.ApplySample("n1", "boot-1", 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	billed, err := reg.ApplySample("n1", "boot-1", 3<<30, 1<<30, 4<<30)
	if err != nil {
		t.Fatal(err)
	}
	if billed != 0 {
		t.Fatalf("за круг из одних замеров списали %d байт", billed)
	}
}
