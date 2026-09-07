// Package enforce turns the oracle's verdicts into something that happens.
//
// Kept apart from the oracle because scoring and acting are different jobs with
// different blast radii: a wrong score is an opinion, a wrong revocation is a
// user with no internet
package enforce

import (
	"context"
	"log"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/oracle"
)

// DefaultInterval is how often verdicts are acted on. Slow on purpose: the score
// is a trend, and reacting inside a second would let one noisy reading cut
// somebody off
const DefaultInterval = time.Minute

// Allocations is what enforcement needs from the allocator
type Allocations interface {
	Revoke(userID string)
}

// Enforcer applies the oracle's decisions
type Enforcer struct {
	judge *oracle.Judge
	alloc Allocations
	// resolve maps a profile id back to the user it was issued to. Signals name a
	// profile because that is all a node knows; the decision is about a person
	resolve  func(profileID string) (string, bool)
	interval time.Duration
	// usage - расход за период, чтобы исчерпанная квота сажала на пол скорости
	usage Usage

	mu sync.Mutex
	// applied remembers what was last acted on, so a client sitting in the same
	// band is not revoked again every minute
	applied map[string]oracle.Band
}

// New builds an enforcer
func New(judge *oracle.Judge, alloc Allocations, resolve func(string) (string, bool)) *Enforcer {
	return &Enforcer{
		judge:    judge,
		alloc:    alloc,
		resolve:  resolve,
		interval: DefaultInterval,
		applied:  map[string]oracle.Band{},
	}
}

// Observe files a signal against the user a profile belongs to
func (e *Enforcer) Observe(signal *fedpb.AbuseSignal, nodeID string) {
	userID, ok := e.resolve(signal.GetProfileId())
	if !ok {
		// A profile nobody has a record of. Usually a stale node still reporting
		// on one that was revoked, which is not an accusation of anybody
		return
	}
	e.judge.Observe(oracle.Signal{
		ClientID: userID,
		Kind:     signal.GetKind(),
		Weight:   signal.GetWeight(),
		Count:    signal.GetCount(),
		// NodeID is kept because it is what makes a donor manufacturing signals
		// against a client visible later
		NodeID: nodeID,
	})
}

// ObserveSubject принимает сигнал, который УЖЕ про участника, а не про профиль.
//
// Нода знает только профиль, поэтому её сигналы идут через Observe с резолвом. А
// разбор на башке и проверка устройств работают с участником напрямую, и если
// подсунуть его в тот же вход, резолв его не найдёт и сигнал молча улетит в
// никуда, никого ни в чём не обвинив
func (e *Enforcer) ObserveSubject(signal *fedpb.AbuseSignal, nodeID string) {
	subject := signal.GetProfileId()
	if subject == "" {
		return
	}
	e.judge.Observe(oracle.Signal{
		ClientID: subject,
		Kind:     signal.GetKind(),
		Weight:   signal.GetWeight(),
		Count:    signal.GetCount(),
		NodeID:   nodeID,
	})
}

// Run applies verdicts until ctx ends
func (e *Enforcer) Run(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, c := range e.Tick() {
				log.Printf("enforce: %s %s -> %s (%s)", c.ClientID, c.From, c.To, c.Why)
			}
		}
	}
}

// Change is one client moving band
type Change struct {
	ClientID string
	From     oracle.Band
	To       oracle.Band
	Why      string
}

// Tick judges everyone with something against them and acts on what changed
func (e *Enforcer) Tick() []Change {
	var changes []Change
	for _, clientID := range e.judge.Accused() {
		verdict := e.judge.Judge(clientID)

		e.mu.Lock()
		previous, seen := e.applied[clientID]
		if seen && previous == verdict.Band {
			e.mu.Unlock()
			continue
		}
		e.applied[clientID] = verdict.Band
		e.mu.Unlock()

		if !seen {
			previous = oracle.BandFull
		}
		changes = append(changes, Change{
			ClientID: clientID, From: previous, To: verdict.Band, Why: verdict.Explain(),
		})

		// Only quarantine revokes. Reduced means fewer nodes, which the allocator
		// applies on the next refresh without cutting anything that is up
		if verdict.Band == oracle.BandQuarantine {
			e.alloc.Revoke(clientID)
		}
	}
	return changes
}

// Band is what a client currently sits in, for the allocator to size its
// assignment by
// Speed - потолки скорости клиента по текущей оценке Oracle. Считается от
// самой оценки: полоса слишком груба, чтобы на неё вешать ещё и скорость.
//
// Исчерпанная квота сажает на пол, а НЕ отрезает. Бесплатный доступ, который
// превращается в кирпич по достижении цифры, человек воспринимает как поломку и
// уходит; медленная связь остаётся связью
func (e *Enforcer) Speed(clientID string) (uplinkBps, downlinkBps uint64) {
	confidence := e.judge.Judge(clientID).Confidence
	if e.overQuota(clientID, confidence) {
		return oracle.FloorSpeed()
	}
	return oracle.SpeedFor(confidence)
}

// overQuota - вышел ли человек за месячный потолок. Потолок появляется только у
// подозрительных, чистым его не выписывают вовсе
func (e *Enforcer) overQuota(clientID string, confidence int) bool {
	if e.usage == nil {
		return false
	}
	limit := oracle.QuotaFor(confidence)
	if limit == oracle.QuotaUnlimited {
		return false
	}
	return e.usage.Usage(clientID) >= limit
}

// SetUsage включает проверку квоты
func (e *Enforcer) SetUsage(usage Usage) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.usage = usage
}

// Usage - сколько человек пронёс за текущий период
type Usage interface {
	Usage(clientID string) uint64
}

// Confidence - оценка Oracle прямо сейчас. Нужна кабинету: в карантине человек
// обязан видеть, насколько ему не доверяют, а не гадать на пустом экране
func (e *Enforcer) Confidence(clientID string) int {
	if e.judge == nil {
		return oracle.StartingConfidence
	}
	return e.judge.Judge(clientID).Confidence
}

func (e *Enforcer) Band(clientID string) oracle.Band {
	e.mu.Lock()
	defer e.mu.Unlock()
	if band, ok := e.applied[clientID]; ok {
		return band
	}
	return oracle.BandFull
}
