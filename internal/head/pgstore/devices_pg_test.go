package pgstore

import (
	"testing"
	"time"

	"wingsnet.org/federation/internal/head/devices"
)

// Полный круг по слоту устройства на живой базе.
//
// Тест существует ровно из-за одной грабли: gorm лепит имя колонки из имени
// поля, HWID превращается в hw_id, а в сыром Where руками было написано hwid.
// Собиралось, мигрировало, и разъёбывалось только в бою: проверка устройства
// падала, а человек получал 503 на подписке
func TestDeviceSlotRoundTrip(t *testing.T) {
	db := testDB(t)
	store := NewDeviceStore(db.Gorm())
	slot := devices.Slot{
		SubjectID: "user-test", HWID: "deadbeef",
		DeviceOS: "android", VerOS: "16", Model: "SM-S938B",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}
	t.Cleanup(func() { _ = store.Drop(slot.SubjectID, slot.HWID) })

	if err := store.Drop(slot.SubjectID, slot.HWID); err != nil {
		t.Fatalf("уборка перед тестом обосралась: %v", err)
	}
	if err := store.Add(slot); err != nil {
		t.Fatalf("слот не завёлся: %v", err)
	}
	later := slot.LastSeen.Add(time.Hour)
	if err := store.Touch(slot.SubjectID, slot.HWID, later); err != nil {
		t.Fatalf("отметка живости обосралась: %v", err)
	}
	got, err := store.SlotsOf(slot.SubjectID)
	if err != nil {
		t.Fatalf("слоты не читаются: %v", err)
	}
	found := false
	for _, s := range got {
		if s.HWID != slot.HWID {
			continue
		}
		found = true
		if !s.LastSeen.After(slot.FirstSeen) {
			t.Fatalf("Touch не доехал до базы: last_seen=%v", s.LastSeen)
		}
	}
	if !found {
		t.Fatalf("своего же устройства не нашли: %+v", got)
	}
}
