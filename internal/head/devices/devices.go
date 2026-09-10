// Package devices держит список устройств, которым разрешено брать подписку.
//
// Сама по себе ссылка - предъявительский ключ, и без второй проверки её хватит
// переслать другу, чтобы он подключился на халяву. Поэтому доступ прибивается к
// устройствам аккаунта, а сколько их положено, решает доверие: чистому побольше,
// подозрительному хуй да маленько
package devices

import (
	"errors"
	"strings"
	"time"
)

var (
	// ErrNoDevice - клиент не назвал себя вообще. Наше приложение шлёт HWID
	// всегда, так что молчит либо чужой клиент, либо кто-то с чужой ссылкой
	ErrNoDevice = errors.New("devices: client did not identify itself")
	// ErrTooManyDevices - слоты заняты живыми устройствами
	ErrTooManyDevices = errors.New("devices: device limit reached")
)

// StaleAfter - сколько слот держится за устройством, которое не появлялось.
// Дальше место отдаётся новому: человек меняет телефон и не должен из-за этой
// ерунды писать в поддержку
const StaleAfter = 21 * 24 * time.Hour

// Slot - одно устройство аккаунта
type Slot struct {
	SubjectID string
	HWID      string
	DeviceOS  string
	VerOS     string
	Model     string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Store - где слоты лежат
type Store interface {
	SlotsOf(subjectID string) ([]Slot, error)
	Touch(subjectID, hwid string, at time.Time) error
	Add(slot Slot) error
	Drop(subjectID, hwid string) error
}

// Limits говорит, сколько устройств положено этому участнику
type Limits interface {
	DevicesFor(subjectID string) int
}

// Registry решает, пускать ли устройство
type Registry struct {
	store  Store
	limits Limits
	now    func() time.Time
	stale  time.Duration
}

func New(store Store, limits Limits) *Registry {
	return &Registry{store: store, limits: limits, now: time.Now, stale: StaleAfter}
}

// Fingerprint - то, чем клиент себя назвал
type Fingerprint struct {
	HWID     string
	DeviceOS string
	VerOS    string
	Model    string
}

// Admit пускает устройство или объясняет, какого хуя нет.
//
// Знакомое просто отмечается. Новое занимает свободный слот, а когда свободных
// нет - выбивает то, что дольше всех молчало. Если все слоты заняты живыми
// устройствами, доступа не будет: это ровно тот случай, когда ссылку раздали
// дальше по друзьям
func (r *Registry) Admit(subjectID string, fp Fingerprint) error {
	hwid := normalize(fp.HWID)
	if hwid == "" {
		return ErrNoDevice
	}
	now := r.now()
	slots, err := r.store.SlotsOf(subjectID)
	if err != nil {
		return err
	}
	for _, slot := range slots {
		if slot.HWID == hwid {
			return r.store.Touch(subjectID, hwid, now)
		}
	}

	limit := r.limits.DevicesFor(subjectID)
	if limit <= 0 {
		return ErrTooManyDevices
	}
	if len(slots) >= limit {
		oldest, ok := oldestStale(slots, now.Add(-r.stale))
		if !ok {
			return ErrTooManyDevices
		}
		if err := r.store.Drop(subjectID, oldest.HWID); err != nil {
			return err
		}
	}
	return r.store.Add(Slot{
		SubjectID: subjectID,
		HWID:      hwid,
		DeviceOS:  clip(fp.DeviceOS),
		VerOS:     clip(fp.VerOS),
		Model:     clip(fp.Model),
		FirstSeen: now,
		LastSeen:  now,
	})
}

// oldestStale ищет слот, который давно молчит
func oldestStale(slots []Slot, before time.Time) (Slot, bool) {
	var pick Slot
	found := false
	for _, slot := range slots {
		if !slot.LastSeen.Before(before) {
			continue
		}
		if !found || slot.LastSeen.Before(pick.LastSeen) {
			pick, found = slot, true
		}
	}
	return pick, found
}

func normalize(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		value = value[:128]
	}
	return value
}

// clip режет то, что показывается человеку. Значения приходят от клиента, и
// принимать оттуда килобайт в поле модели незачем
func clip(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
