package nodetrust

import (
	"testing"
	"time"
)

func testAudit(now *time.Time) (*WatchAudit, *Judge) {
	judge := NewJudge()
	judge.now = func() time.Time { return *now }
	audit := NewWatchAudit(judge)
	audit.now = func() time.Time { return *now }
	return audit, judge
}

// Нода возит трафик и молчит про домены: доверие обязано просесть
func TestSilentNodeLosesTrust(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	audit, judge := testAudit(&at)

	totals := map[string]uint64{"n1": 0}
	audit.Sweep(totals)
	totals["n1"] = 4 << 30
	at = at.Add(2 * time.Hour)
	audit.Sweep(totals)

	if v := judge.Judge("n1"); v.Trust >= StartingTrust {
		t.Fatalf("молчание не наказано: %d", v.Trust)
	}
}

// Стучащая нода не трогается, и молчание без трафика тоже законно
func TestReportingNodeKeepsTrust(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	audit, judge := testAudit(&at)

	totals := map[string]uint64{"loud": 0, "idle": 0}
	audit.Sweep(totals)
	totals["loud"], totals["idle"] = 4<<30, 1<<20
	at = at.Add(30 * time.Minute)
	audit.ObserveDomains("loud")
	audit.Sweep(totals)
	at = at.Add(2 * time.Hour)
	audit.Sweep(totals)

	if v := judge.Judge("loud"); v.Trust != StartingTrust {
		t.Fatalf("честную ноду наказали: %d", v.Trust)
	}
	if v := judge.Judge("idle"); v.Trust != StartingTrust {
		t.Fatalf("тихую без трафика наказали: %d", v.Trust)
	}
}

// Одно молчание - одна претензия за окно, а не по штуке на каждый проход
func TestSilenceAccusedOncePerWindow(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	audit, judge := testAudit(&at)

	totals := map[string]uint64{"n1": 0}
	audit.Sweep(totals)
	totals["n1"] = 4 << 30
	at = at.Add(2 * time.Hour)
	audit.Sweep(totals)
	first := judge.Judge("n1").Trust
	audit.Sweep(totals)
	audit.Sweep(totals)

	if got := judge.Judge("n1").Trust; got != first {
		t.Fatalf("наказали повторно: было %d, стало %d", first, got)
	}
}

// Релей, не запертый на своём WireGuard, может увести трафик мимо наблюдения
func TestUnmanagedRelayLosesTrust(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	audit, judge := testAudit(&at)

	audit.ObserveRelayMode("good", true)
	audit.ObserveRelayMode("bad", false)

	if v := judge.Judge("good"); v.Trust != StartingTrust {
		t.Fatalf("запертый релей наказали: %d", v.Trust)
	}
	if v := judge.Judge("bad"); v.Trust >= StartingTrust {
		t.Fatalf("увод не наказан: %d", v.Trust)
	}
}

// Перезапуск ноды сбрасывает её счётчики, и разница уходит в минус: молчание
// после этого всё равно обязано ловиться
func TestRestartDoesNotHideSilence(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	audit, judge := testAudit(&at)

	totals := map[string]uint64{"n1": 8 << 30}
	audit.Sweep(totals)
	totals["n1"] = 1 << 20
	audit.Sweep(totals)
	totals["n1"] = 5 << 30
	at = at.Add(2 * time.Hour)
	audit.Sweep(totals)

	if v := judge.Judge("n1"); v.Trust >= StartingTrust {
		t.Fatalf("молчание после рестарта проехало: %d", v.Trust)
	}
}
