package devices

import (
	"errors"
	"testing"
	"time"
)

type memStore struct {
	slots map[string][]Slot
}

func newMem() *memStore { return &memStore{slots: map[string][]Slot{}} }

func (m *memStore) SlotsOf(subjectID string) ([]Slot, error) { return m.slots[subjectID], nil }

func (m *memStore) Touch(subjectID, hwid string, at time.Time) error {
	for i, slot := range m.slots[subjectID] {
		if slot.HWID == hwid {
			m.slots[subjectID][i].LastSeen = at
			return nil
		}
	}
	return errors.New("нет такого слота")
}

func (m *memStore) Add(slot Slot) error {
	m.slots[slot.SubjectID] = append(m.slots[slot.SubjectID], slot)
	return nil
}

func (m *memStore) Drop(subjectID, hwid string) error {
	kept := m.slots[subjectID][:0]
	for _, slot := range m.slots[subjectID] {
		if slot.HWID != hwid {
			kept = append(kept, slot)
		}
	}
	m.slots[subjectID] = kept
	return nil
}

type fixedLimit int

func (f fixedLimit) DevicesFor(string) int { return int(f) }

func registryAt(store Store, limit int, now time.Time) *Registry {
	r := New(store, fixedLimit(limit))
	r.now = func() time.Time { return now }
	return r
}

func TestSilentClientIsRefused(t *testing.T) {
	r := registryAt(newMem(), 5, time.Now())
	if err := r.Admit("user-1", Fingerprint{}); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("клиент без hwid прошёл: %v", err)
	}
}

func TestKnownDeviceJustGetsTouched(t *testing.T) {
	store := newMem()
	start := time.Unix(1_700_000_000, 0)
	r := registryAt(store, 2, start)
	if err := r.Admit("user-1", Fingerprint{HWID: "aaa"}); err != nil {
		t.Fatalf("первое устройство не пустили: %v", err)
	}
	later := start.Add(time.Hour)
	r.now = func() time.Time { return later }
	if err := r.Admit("user-1", Fingerprint{HWID: "aaa"}); err != nil {
		t.Fatalf("своё же устройство не пустили: %v", err)
	}
	if got := len(store.slots["user-1"]); got != 1 {
		t.Fatalf("завели %d слотов вместо одного", got)
	}
	if !store.slots["user-1"][0].LastSeen.Equal(later) {
		t.Fatal("отметку о заходе не обновили")
	}
}

func TestLiveDevicesAreNotEvicted(t *testing.T) {
	store := newMem()
	now := time.Unix(1_700_000_000, 0)
	r := registryAt(store, 2, now)
	if err := r.Admit("user-1", Fingerprint{HWID: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Admit("user-1", Fingerprint{HWID: "tablet"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Admit("user-1", Fingerprint{HWID: "stranger"}); !errors.Is(err, ErrTooManyDevices) {
		t.Fatalf("чужого пустили поверх живых устройств: %v", err)
	}
	if got := len(store.slots["user-1"]); got != 2 {
		t.Fatalf("слотов стало %d, лимит два", got)
	}
}

func TestStaleDeviceGivesUpItsSlot(t *testing.T) {
	store := newMem()
	old := time.Unix(1_700_000_000, 0)
	r := registryAt(store, 1, old)
	if err := r.Admit("user-1", Fingerprint{HWID: "old-phone"}); err != nil {
		t.Fatal(err)
	}
	// Через месяц старый телефон уже месяц не появлялся
	later := old.Add(StaleAfter + 24*time.Hour)
	r.now = func() time.Time { return later }
	if err := r.Admit("user-1", Fingerprint{HWID: "new-phone"}); err != nil {
		t.Fatalf("новый телефон не пустили на место протухшего: %v", err)
	}
	slots := store.slots["user-1"]
	if len(slots) != 1 || slots[0].HWID != "new-phone" {
		t.Fatalf("слот не переехал: %+v", slots)
	}
}

func TestQuarantineLeavesNoSlots(t *testing.T) {
	r := registryAt(newMem(), 0, time.Now())
	if err := r.Admit("user-1", Fingerprint{HWID: "phone"}); !errors.Is(err, ErrTooManyDevices) {
		t.Fatalf("в карантине выдали слот: %v", err)
	}
}
