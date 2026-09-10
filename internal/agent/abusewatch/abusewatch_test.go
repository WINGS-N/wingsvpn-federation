package abusewatch

import (
	"context"
	"errors"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// sampleUntilSustained гоняет опросы, двигая часы, пока картина не продержится
// достаточно долго, чтобы её посчитали настоящей
func sampleUntilSustained(w *Watcher) {
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i <= int(sustain/DefaultInterval)+1; i++ {
		at := base.Add(time.Duration(i) * DefaultInterval)
		w.now = func() time.Time { return at }
		w.Sample(context.Background())
	}
}

type fakeCore struct {
	ips   map[string]map[string]int64
	asked []string
	err   error
}

func (f *fakeCore) OnlineIPs(_ context.Context, email string) (map[string]int64, error) {
	f.asked = append(f.asked, email)
	if f.err != nil {
		return nil, f.err
	}
	return f.ips[email], nil
}

type fakeProfiles struct{ metered map[string]string }

func (f *fakeProfiles) MeteredProfiles() map[string]string { return f.metered }

func addresses(n int) map[string]int64 {
	out := make(map[string]int64, n)
	for i := 0; i < n; i++ {
		out[string(rune('a'+i))+".addr"] = 1
	}
	return out
}

// One profile from forty addresses is a resold account. A phone plus a laptop is
// not, and accusing that user costs them their access
func TestOnlyRealFanoutIsReported(t *testing.T) {
	core := &fakeCore{ips: map[string]map[string]int64{
		"f-shared": addresses(12),
		"f-normal": addresses(2),
	}}
	w := New(core, &fakeProfiles{metered: map[string]string{
		"f-shared": "profile-shared",
		"f-normal": "profile-normal",
	}})
	sampleUntilSustained(w)

	got := w.DrainAbuse()
	if len(got) != 1 {
		t.Fatalf("reported %d signals, want only the shared profile", len(got))
	}
	if got[0].GetProfileId() != "profile-shared" {
		t.Errorf("accused %s", got[0].GetProfileId())
	}
	if got[0].GetKind() != fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT {
		t.Errorf("kind = %v", got[0].GetKind())
	}
	if got[0].GetCount() != 12 {
		t.Errorf("count = %d", got[0].GetCount())
	}
}

// The donor's own paying clients on vanilla apps are not part of this and must
// never be watched. This is the invariant, not a nicety
func TestUnmeteredProfilesAreNeverEvenAskedAbout(t *testing.T) {
	core := &fakeCore{ips: map[string]map[string]int64{
		"paying-customer": addresses(40),
		"f-free":          addresses(1),
	}}
	w := New(core, &fakeProfiles{metered: map[string]string{"f-free": "profile-free"}})
	w.Sample(context.Background())

	for _, asked := range core.asked {
		if asked == "paying-customer" {
			t.Fatal("the donor's own client was watched")
		}
	}
	if len(w.DrainAbuse()) != 0 {
		t.Error("an accusation came out of a fleet with nothing wrong in it")
	}
}

// A signal never says where anybody went, only that a pattern was seen
func TestSignalsCarryNoDestination(t *testing.T) {
	core := &fakeCore{ips: map[string]map[string]int64{"f-a": addresses(9)}}
	w := New(core, &fakeProfiles{metered: map[string]string{"f-a": "p1"}})
	sampleUntilSustained(w)
	got := w.DrainAbuse()
	if len(got) != 1 {
		t.Fatal("expected one signal")
	}
	// The message has no field for it, and that is the point: check the shape has
	// not grown one
	if got[0].String() == "" {
		t.Fatal("empty signal")
	}
	fields := got[0].ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		switch name := string(fields.Get(i).Name()); name {
		case "domain", "url", "ip", "address", "destination":
			t.Errorf("AbuseSignal grew a %q field", name)
		}
	}
}

// Draining twice must not accuse the same user again from one reading
func TestDrainingClearsWhatWasReported(t *testing.T) {
	core := &fakeCore{ips: map[string]map[string]int64{"f-a": addresses(9)}}
	w := New(core, &fakeProfiles{metered: map[string]string{"f-a": "p1"}})
	sampleUntilSustained(w)
	if len(w.DrainAbuse()) != 1 {
		t.Fatal("first drain came back empty")
	}
	if got := w.DrainAbuse(); len(got) != 0 {
		t.Errorf("second drain repeated %d signals", len(got))
	}
}

// A core that will not answer is not evidence against anybody
func TestACoreThatFailsAccusesNobody(t *testing.T) {
	core := &fakeCore{err: errors.New("core down")}
	w := New(core, &fakeProfiles{metered: map[string]string{"f-a": "p1"}})
	w.Sample(context.Background())
	if got := w.DrainAbuse(); len(got) != 0 {
		t.Errorf("a broken core produced %d accusations", len(got))
	}
}

// A busy fleet must not grow the queue without limit
func TestTheQueueIsBounded(t *testing.T) {
	core := &fakeCore{ips: map[string]map[string]int64{"f-a": addresses(9)}}
	w := New(core, &fakeProfiles{metered: map[string]string{"f-a": "p1"}})
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < queueDepth*3; i++ {
		// Час между опросами: иначе повтор обвинения придушен паузой и очередь
		// не наполнится вовсе
		at := base.Add(time.Duration(i) * (sustain + repeatEvery))
		w.now = func() time.Time { return at }
		w.Sample(context.Background())
		w.Sample(context.Background())
	}
	if got := len(w.DrainAbuse()); got > queueDepth {
		t.Errorf("queued %d signals, want at most %d", got, queueDepth)
	}
}

// Разовое совпадение - не обвинение: у прошлого VPN бывает затяжной выход
func TestAFlickerIsForgiven(t *testing.T) {
	core := &fakeCore{ips: map[string]map[string]int64{"f-a": addresses(9)}}
	w := New(core, &fakeProfiles{metered: map[string]string{"f-a": "p1"}})
	base := time.Unix(1_700_000_000, 0)
	w.now = func() time.Time { return base }
	w.Sample(context.Background())
	w.now = func() time.Time { return base.Add(DefaultInterval) }
	w.Sample(context.Background())
	if got := w.DrainAbuse(); len(got) != 0 {
		t.Fatalf("минутное совпадение записали в обвинение: %d", len(got))
	}
}

// Разрыв обнуляет счёт: картина, которая расходилась, копиться не должна
func TestAGapResetsTheStreak(t *testing.T) {
	core := &fakeCore{ips: map[string]map[string]int64{"f-a": addresses(9)}}
	w := New(core, &fakeProfiles{metered: map[string]string{"f-a": "p1"}})
	base := time.Unix(1_700_000_000, 0)
	w.now = func() time.Time { return base }
	w.Sample(context.Background())
	// Через полчаса это уже другая история, а не продолжение прошлой
	w.now = func() time.Time { return base.Add(30 * time.Minute) }
	w.Sample(context.Background())
	if got := w.DrainAbuse(); len(got) != 0 {
		t.Fatalf("после разрыва обвинили как за непрерывный разброс: %d", len(got))
	}
}
