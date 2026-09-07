package intake

import (
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/pkg/addrhash"
)

// seenTTL - сколько отпечаток считается свежим. Мобильный адрес живёт недолго,
// и сверять заявленное сегодня с тем, что нода видела вчера, значит обвинять за
// смену вышки
const seenTTL = 30 * time.Minute

// AddressBook держит отпечатки адресов, с которых работают профили
type AddressBook struct {
	mu sync.Mutex
	// bySubject - отпечатки на участника, с временем последнего обновления
	bySubject map[string]addressEntry
	resolve   func(profileID string) (string, bool)
	now       func() time.Time
}

type addressEntry struct {
	hashes [][]byte
	at     time.Time
}

// NewAddressBook строит книгу поверх резолва профиля в участника
func NewAddressBook(resolve func(string) (string, bool)) *AddressBook {
	return &AddressBook{
		bySubject: map[string]addressEntry{},
		resolve:   resolve,
		now:       time.Now,
	}
}

// Record складывает то, что прислала нода
func (a *AddressBook) Record(batch *fedpb.DomainBatch) {
	if batch == nil || len(batch.GetAddresses()) == 0 {
		return
	}
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, item := range batch.GetAddresses() {
		subject := item.GetProfileId()
		if a.resolve != nil {
			owner, ok := a.resolve(item.GetProfileId())
			if !ok {
				continue
			}
			subject = owner
		}
		// Профиль у человека не один, поэтому отпечатки складываются, а не
		// затирают друг друга: иначе вторая нода стёрла бы адрес первой
		entry := a.bySubject[subject]
		if now.Sub(entry.at) > seenTTL {
			entry.hashes = nil
		}
		entry.hashes = append(entry.hashes, item.GetAddrHash()...)
		entry.at = now
		a.bySubject[subject] = entry
	}
}

// Matches говорит, видела ли хоть одна нода этот адрес у участника. Второй
// ответ - было ли вообще что сверять
func (a *AddressBook) Matches(subjectID, claimed string) (match bool, known bool) {
	a.mu.Lock()
	entry, ok := a.bySubject[subjectID]
	fresh := ok && a.now().Sub(entry.at) <= seenTTL
	hashes := entry.hashes
	a.mu.Unlock()
	if !fresh || len(hashes) == 0 {
		return false, false
	}
	return addrhash.Matches(claimed, hashes), true
}
