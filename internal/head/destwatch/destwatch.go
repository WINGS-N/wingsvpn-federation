// Package destwatch keeps the fleet's REALITY dest alive without anybody typing
// one in.
//
// A dest is not a setting you choose once. The host it borrows a TLS identity
// from can stop answering, lose the certificate the handshake copies, or become
// unreachable from the country the users are actually in - and every one of
// those turns the whole fleet into inbounds that fail at the handshake while the
// nodes still report themselves healthy.
//
// So the head re-checks the current dest on a timer and, when it no longer
// holds up, picks another from the pool it already probes. The operator can
// still pin one by hand; this only runs when they asked for automatic.
package destwatch

import (
	"context"
	"log"
	"math/rand"
	"time"

	"wingsnet.org/federation/internal/head/fleet"
	"wingsnet.org/federation/internal/scan"
)

// Settings is the slice of the fleet manager this watcher drives
type Settings interface {
	Settings() fleet.Settings
	Update(fleet.Settings) (fleet.Settings, error)
}

// Prober finds dests that hold up. Injected so the watcher can be tested
// without reaching the network.
type Prober func(ctx context.Context) ([]*scan.Result, error)

// Watcher re-picks the dest when the current one stops being usable
type Watcher struct {
	fleet  Settings
	probe  Prober
	every  time.Duration
	rand   *rand.Rand
	notify func()
}

// Options configures a Watcher
type Options struct {
	Fleet Settings
	Probe Prober
	// Every is how often the current dest is re-checked. Hours, not minutes: a
	// dest that works is not going to stop working between two coffee breaks,
	// and every check is a handshake to somebody else's server from every head.
	Every time.Duration
	// Notify runs after the dest changed, so the caller can re-render and push
	// the config that carries it
	Notify func()
	Rand   *rand.Rand
}

// New builds a watcher
func New(o Options) *Watcher {
	every := o.Every
	if every <= 0 {
		every = 6 * time.Hour
	}
	r := o.Rand
	if r == nil {
		r = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return &Watcher{fleet: o.Fleet, probe: o.Probe, every: every, rand: r, notify: o.Notify}
}

// Run checks once at start and then on the timer, until ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	w.checkOnce(ctx)
	ticker := time.NewTicker(w.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.checkOnce(ctx)
		}
	}
}

func (w *Watcher) checkOnce(ctx context.Context) {
	cur := w.fleet.Settings()
	if !cur.AutoDest {
		return
	}
	results, err := w.probe(ctx)
	if err != nil {
		// Не трогаем рабочий dest из-за неудачной проверки: сеть башки могла
		// моргнуть, а смена dest перезапускает Xray на всём флоте
		log.Printf("destwatch: probe failed, keeping %q: %v", cur.RealityDest, err)
		return
	}
	usable := make([]*scan.Result, 0, len(results))
	for _, r := range results {
		if r.Feasible {
			usable = append(usable, r)
		}
	}
	if len(usable) == 0 {
		log.Printf("destwatch: nothing in the pool held up, keeping %q", cur.RealityDest)
		return
	}
	// Пул обновляем всегда, даже когда текущий dest ещё держится: список годных
	// целей меняется, и ноды должны разъезжаться по свежему
	stillGood := false
	for _, r := range usable {
		if r.Target == cur.RealityDest {
			stillGood = true
			break
		}
	}
	if stillGood && samePool(cur.DestPool, usable) {
		return
	}

	// В пул идут все, кто прошёл проверку: ноды разбираются по нему, чтобы одна
	// заблокированная цель не роняла флот целиком
	pool := make([]string, 0, len(usable))
	for _, r := range usable {
		pool = append(pool, r.Target)
	}

	// Перечитываем перед записью: скан идёт минутами, и за это время оператор
	// мог поменять настройки в панели. Снимок, взятый до скана, вернул бы их
	// назад - именно так тут потерялся включённый ML-DSA-65
	next := w.fleet.Settings()
	next.DestPool = pool
	if stillGood {
		// Пул освежили, а рабочий dest оставили: смена перезапускает Xray на
		// всём флоте, и делать это ради обновления списка нечестно
		if _, err := w.fleet.Update(next); err != nil {
			log.Printf("destwatch: could not store the pool: %v", err)
			return
		}
		log.Printf("destwatch: pool refreshed to %d dests, kept %q", len(pool), cur.RealityDest)
		if w.notify != nil {
			w.notify()
		}
		return
	}

	// Случайный из годных, а не первый: одинаковый dest на каждом развёртывании
	// делает флот узнаваемым по одному признаку
	chosen := usable[w.rand.Intn(len(usable))]
	next.RealityDest = chosen.Target
	// Автовыбор мог быть выключен, пока шёл скан - тогда решает человек
	if !next.AutoDest {
		return
	}
	if _, err := w.fleet.Update(next); err != nil {
		log.Printf("destwatch: could not store the new dest: %v", err)
		return
	}
	log.Printf("destwatch: dest %q no longer usable, moved the fleet to %q", cur.RealityDest, chosen.Target)
	if w.notify != nil {
		w.notify()
	}
}

// samePool reports whether the verified set is the one already stored, so an
// unchanged pool does not bump the config version and restart Xray for nothing.
func samePool(have []string, found []*scan.Result) bool {
	if len(have) != len(found) {
		return false
	}
	seen := make(map[string]bool, len(have))
	for _, t := range have {
		seen[t] = true
	}
	for _, r := range found {
		if !seen[r.Target] {
			return false
		}
	}
	return true
}
