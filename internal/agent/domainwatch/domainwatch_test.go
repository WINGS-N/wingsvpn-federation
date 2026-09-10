package domainwatch

import (
	"testing"

	xraypb "wingsnet.org/federation/gen/xraypb"
)

type fakeProfiles map[string]string

func (f fakeProfiles) MeteredProfiles() map[string]string { return f }

func TestVanillaClientsAreNeverWatched(t *testing.T) {
	w := New(fakeProfiles{"f-abc12345": "profile-1"})
	w.Observe(&xraypb.AccessEvent{Email: "paying-customer@example.com", TargetDomain: "bank.example"})
	if batch := w.Drain(); batch != nil {
		t.Fatal("подсмотрели за клиентом донора, а он к федерации отношения не имеет")
	}
}

func TestSamplesFoldIntoOneCounter(t *testing.T) {
	w := New(fakeProfiles{"f-abc12345": "profile-1"})
	for i := 0; i < 3; i++ {
		w.Observe(&xraypb.AccessEvent{
			Email: "f-abc12345", TargetDomain: "Example.COM.", AtUnixNano: int64(1_700_000_000+i) * 1e9,
			UpBytes: 100, DownBytes: 900, DurationMs: 1000,
		})
	}
	w.Observe(&xraypb.AccessEvent{
		Email: "f-abc12345", TargetDomain: "example.com", AtUnixNano: 1_700_000_010 * 1e9,
		DurationMs: longLivedMs + 1,
	})

	batch := w.Drain()
	if batch == nil || len(batch.GetSamples()) != 1 {
		t.Fatalf("домен размазало по нескольким ключам: %+v", batch)
	}
	got := batch.GetSamples()[0]
	if got.GetDomain() != "example.com" {
		t.Fatalf("имя не привели к одному виду: %q", got.GetDomain())
	}
	if got.GetCount() != 4 {
		t.Fatalf("насчитали %d заходов вместо 4", got.GetCount())
	}
	if got.GetDownBytes() != 2700 || got.GetUpBytes() != 300 {
		t.Fatalf("объём не сошёлся: up=%d down=%d", got.GetUpBytes(), got.GetDownBytes())
	}
	if got.GetLongLived() != 1 {
		t.Fatalf("долгие соединения посчитали как %d вместо 1", got.GetLongLived())
	}
	if got.GetFirstSeenUnix() != 1_700_000_000 || got.GetLastSeenUnix() != 1_700_000_010 {
		t.Fatalf("окно поехало: %d..%d", got.GetFirstSeenUnix(), got.GetLastSeenUnix())
	}
}

func TestDrainForgetsEverything(t *testing.T) {
	w := New(fakeProfiles{"f-abc12345": "profile-1"})
	w.Observe(&xraypb.AccessEvent{Email: "f-abc12345", TargetDomain: "example.com"})
	if w.Drain() == nil {
		t.Fatal("первый отчёт пустой")
	}
	if w.Drain() != nil {
		t.Fatal("на ноде осталось наблюдение после отправки, а не должно оставаться нихуя")
	}
}

func TestBareAddressIsCountedByPort(t *testing.T) {
	w := New(fakeProfiles{"f-abc12345": "profile-1"})
	for _, ip := range []string{"203.0.113.9", "203.0.113.10", "203.0.113.9"} {
		w.Observe(&xraypb.AccessEvent{
			Email: "f-abc12345", TargetIp: ip, TargetPort: 6881, DownBytes: 100,
		})
	}
	batch := w.Drain()
	if batch == nil || len(batch.GetSamples()) != 0 {
		t.Fatalf("безымянное соединение записали как домен: %+v", batch)
	}
	if len(batch.GetPorts()) != 1 {
		t.Fatalf("порты не посчитали: %+v", batch.GetPorts())
	}
	got := batch.GetPorts()[0]
	if got.GetPort() != 6881 || got.GetCount() != 3 || got.GetDistinctTargets() != 2 {
		t.Fatalf("порт посчитали криво: %+v", got)
	}
}

func TestMailPortIsSeenEvenWithADomain(t *testing.T) {
	w := New(fakeProfiles{"f-abc12345": "profile-1"})
	w.Observe(&xraypb.AccessEvent{Email: "f-abc12345", TargetDomain: "relay.example", TargetPort: 587})
	batch := w.Drain()
	if batch == nil || len(batch.GetSamples()) != 1 || batch.GetSamples()[0].GetPort() != 587 {
		t.Fatalf("порт у домена потеряли: %+v", batch)
	}
}

func TestOverflowIsCountedNotSilent(t *testing.T) {
	w := New(fakeProfiles{"f-abc12345": "profile-1"})
	for i := 0; i < maxSamples+5; i++ {
		w.Observe(&xraypb.AccessEvent{Email: "f-abc12345", TargetDomain: domainOf(i)})
	}
	batch := w.Drain()
	if batch == nil || len(batch.GetSamples()) != maxSamples {
		t.Fatalf("отчёт не ограничили: %d", len(batch.GetSamples()))
	}
	if batch.GetDropped() == 0 {
		t.Fatal("переполнение проглотили молча")
	}
}

func domainOf(i int) string {
	return "host" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26)) + ".example"
}
