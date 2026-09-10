// Package abusewatch лепит сигналы из того, что ядро и так про себя знает.
//
// Спрашивает у Xray, с каких адресов подключён каждый профиль, и больше ничего.
// Дешёвый сигнал в реальном времени, снимается опросом раз в полминуты. Куда шли
// соединения, собирает domainwatch отдельным путём
package abusewatch

import (
	"context"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/agent/geo"
	"wingsnet.org/federation/pkg/addrhash"
)

// DefaultInterval is how often the core is asked. Profile sharing is a pattern
// over minutes, not a thing to catch in the same second
const DefaultInterval = 30 * time.Second

// fanoutThreshold is how many simultaneous addresses on one profile stop looking
// like a phone plus a laptop and start looking like a resold account. Generous:
// a real user on mobile roams between addresses, and a false accusation costs
// them their access
const fanoutThreshold = 6

// queueDepth bounds what is held for the head. Signals are a trend, so an old
// backlog is worth less than a fresh reading and dropping is the right failure
const queueDepth = 64

// geoSpreadKm - расстояние, после которого одновременная работа перестаёт быть
// поездкой. Смена оператора признаком не считается: домашний провайдер и сотовый
// у одного человека - обычное дело, как и динамический адрес на каждом коннекте
const geoSpreadKm = 700

// sustain - сколько разброс должен держаться, чтобы считаться настоящим.
//
// Мгновенный снимок врёт: у прошлого VPN бывает затяжной выход, и полминуты
// одновременных адресов из двух стран это не раздача профиля, а нормальная
// пересменка. Обвинять есть смысл только когда оба конца живут и по ним ходят
const sustain = 5 * time.Minute

// repeatEvery - как часто повторять обвинение, пока картина не изменилась. Без
// паузы один непрерывный разброс сыпал бы сигнал каждые полминуты и топил
// человека за одно и то же
const repeatEvery = time.Hour

// Places разбирает адреса в места и сети по локальной базе. nil, когда базы нет
type Places interface {
	Spread(addrs []string) geo.Reading
}

// Core is the part of Xray's API this needs
type Core interface {
	OnlineIPs(ctx context.Context, email string) (map[string]int64, error)
}

// Profiles reports which profiles may be watched at all
type Profiles interface {
	// MeteredProfiles maps the Xray email tag to the profile id, for federation
	// profiles only
	MeteredProfiles() map[string]string
}

// Watcher polls the core and queues signals for the head
type Watcher struct {
	core     Core
	profiles Profiles
	places   Places
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	pending []*fedpb.AbuseSignal
	// addresses - отпечатки адресов, с которых профиль сейчас работает. Башка
	// сверяет их с тем, что клиент заявил о себе сам
	addresses map[string][][]byte
	// streaks помнит, с какого момента держится картина по каждому профилю
	streaks map[streakKey]streak
}

// streakKey - профиль и класс, по которым копится устойчивость
type streakKey struct {
	profileID string
	kind      fedpb.AbuseKind
}

type streak struct {
	since    time.Time
	seen     time.Time
	reported time.Time
}

// SetPlaces enables the geo signal. Без неё остаётся только счёт адресов
func (w *Watcher) SetPlaces(p Places) { w.places = p }

// New builds a watcher
func New(core Core, profiles Profiles) *Watcher {
	return &Watcher{
		core: core, profiles: profiles, interval: DefaultInterval,
		now: time.Now, streaks: map[streakKey]streak{},
		addresses: map[string][][]byte{},
	}
}

// Run polls until ctx ends
func (w *Watcher) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Sample(ctx)
		}
	}
}

// Sample takes one reading
func (w *Watcher) Sample(ctx context.Context) {
	for email, profileID := range w.profiles.MeteredProfiles() {
		ips, err := w.core.OnlineIPs(ctx, email)
		if err != nil || len(ips) == 0 {
			continue
		}
		w.rememberAddresses(profileID, ips)
		if w.places != nil && len(ips) > 1 {
			addrs := make([]string, 0, len(ips))
			for addr := range ips {
				addrs = append(addrs, addr)
			}
			r := w.places.Spread(addrs)
			spread := r.Places > 1 && r.MaxKm >= geoSpreadKm
			// Сотни километров: башке нужен порядок величины, точное
			// расстояние сузило бы место до города
			w.track(profileID, fedpb.AbuseKind_ABUSE_KIND_GEO_SPREAD, spread, uint32(r.MaxKm/100))
		}
		w.track(profileID, fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT,
			len(ips) >= fanoutThreshold, uint32(len(ips)))
	}
}

// track копит устойчивость и ставит сигнал в очередь, только когда картина
// продержалась. Разовое совпадение прощается молча
func (w *Watcher) track(profileID string, kind fedpb.AbuseKind, present bool, count uint32) {
	now := w.now()
	k := streakKey{profileID: profileID, kind: kind}
	if !present {
		delete(w.streaks, k)
		return
	}
	entry, ok := w.streaks[k]
	// Разрыв длиннее двух опросов означает, что картина уже расходилась, и
	// копить с прошлого раза нечестно
	if !ok || now.Sub(entry.seen) > 2*w.interval {
		w.streaks[k] = streak{since: now, seen: now}
		return
	}
	entry.seen = now
	defer func() { w.streaks[k] = entry }()
	if now.Sub(entry.since) < sustain {
		return
	}
	if !entry.reported.IsZero() && now.Sub(entry.reported) < repeatEvery {
		return
	}
	entry.reported = now
	w.queue(&fedpb.AbuseSignal{
		ProfileId: profileID,
		Kind:      kind,
		Count:     count,
		// The window is what the reading covers, so the head can weigh a
		// burst differently from a steady state
		WindowSeconds: uint32(now.Sub(entry.since).Seconds()),
	})
}

func (w *Watcher) queue(signal *fedpb.AbuseSignal) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) >= queueDepth {
		w.pending = w.pending[1:]
	}
	w.pending = append(w.pending, signal)
}

// rememberAddresses складывает отпечатки. Сами адреса остаются тут и наверх не
// едут: башке нужно только сверить их с заявленным, а для этого адрес не нужен
func (w *Watcher) rememberAddresses(profileID string, ips map[string]int64) {
	if len(ips) == 0 {
		return
	}
	hashes := make([][]byte, 0, len(ips))
	for addr := range ips {
		if h := addrhash.Of(addr); h != nil {
			hashes = append(hashes, h)
		}
	}
	w.mu.Lock()
	w.addresses[profileID] = hashes
	w.mu.Unlock()
}

// DrainAddresses отдаёт отпечатки и забывает их
func (w *Watcher) DrainAddresses() []*fedpb.ClientAddresses {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.addresses) == 0 {
		return nil
	}
	out := make([]*fedpb.ClientAddresses, 0, len(w.addresses))
	for profileID, hashes := range w.addresses {
		out = append(out, &fedpb.ClientAddresses{ProfileId: profileID, AddrHash: hashes})
	}
	w.addresses = map[string][][]byte{}
	return out
}

// DrainAbuse hands over what has been seen and forgets it
func (w *Watcher) DrainAbuse() []*fedpb.AbuseSignal {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) == 0 {
		return nil
	}
	out := w.pending
	w.pending = nil
	return out
}
