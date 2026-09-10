// Package aggregator folds per-node samples into the numbers the panel and the
// public counter show
package aggregator

import (
	"sort"
	"sync"
	"time"
)

// staleAfter is how long a node's numbers keep counting once it stops reporting.
// Short, because a dead node that keeps contributing to a live speed readout
// makes the whole counter a lie
const staleAfter = 15 * time.Second

// sharedLag - фора нодам соседней реплики. Их отметка едет через общую таблицу
// и опаздывает на два тика синхронизации, поэтому по общему порогу они мигали
// бы: то онлайн, то нет, хотя сэмплы идут каждую секунду
const sharedLag = 20 * time.Second

// Sample is one node's cumulative report
type Sample struct {
	NodeID         string
	DonorID        string
	BootID         string
	UpBytes        uint64
	DownBytes      uint64
	ProbeBytes     uint64
	ActiveSessions uint32
	ActiveStreams  uint32
	At             time.Time
}

// nodeState carries what is needed to derive a rate from cumulative counters
type nodeState struct {
	donorID  string
	bootID   string
	up, down uint64
	probe    uint64
	upRate   float64
	downRate float64
	sessions uint32
	streams  uint32
	// totalUp and totalDown accumulate across reboots, which is why the raw
	// counters cannot be used directly
	totalUp   uint64
	totalDown uint64
	// totalProbe - часть totalUp+totalDown, которую сожгли зонды
	totalProbe uint64
	lastAt     time.Time
}

// Snapshot is what gets rendered
type Snapshot struct {
	NodesTotal  int
	NodesOnline int
	Sessions    uint32
	Streams     uint32
	UpBytes     uint64
	DownBytes   uint64
	UpRateBps   float64
	DownRateBps float64
	// LifetimeBytes is everything the federation has ever carried, both
	// directions. Unlike the figures above it is not derived from the nodes
	// currently known: it survives a restart and a node being forgotten
	LifetimeBytes uint64
	// PeriodBytes - сколько пройдено с начала текущего периода
	PeriodBytes uint64
	// ProbeBytes - сколько из перенесённого сожгли проверки зондов
	ProbeBytes uint64
	At         time.Time
}

// DonorSnapshot is a donor's own view. Aggregates only: there is deliberately no
// way to get from here to who is using the node
type DonorSnapshot struct {
	DonorID     string
	Nodes       int
	NodesOnline int
	Sessions    uint32
	UpBytes     uint64
	DownBytes   uint64
	ProbeBytes  uint64
	UpRateBps   float64
	DownRateBps float64
}

// Aggregator holds per-node state and derives the totals
type Aggregator struct {
	mu    sync.Mutex
	nodes map[string]*nodeState
	now   func() time.Time
	// lifetime is every byte the federation has ever moved. Kept beside the
	// per-node states rather than inside them so that forgetting a node, or
	// restarting the head, does not erase work that was really done
	lifetime uint64
	// periodBase - сколько было пройдено на начало периода. Счётчики нод живут
	// в памяти и обнуляются с рестартом башки, а период обязан пережить выкат
	periodBase uint64
	// shared - ноды, которые держит другая реплика. Своих тут нет: их мы знаем
	// точнее из собственной памяти
	shared map[string]NodeShare
	// seed - накопленное, поднятое из общего места при старте. Память реплики
	// пуста после перезапуска, и без этого нода начинала бы счёт заново, а
	// расписки клиентов, которые лежат в базе, оставались бы больше её отчёта
	seed map[string]NodeShare
	// onDelta gets every closed delta with the donor it belongs to, so the
	// monthly history is written from the same numbers the counters show
	onDelta func(donorID string, at time.Time, bytes uint64)
}

// New builds an empty aggregator
func New() *Aggregator {
	return &Aggregator{nodes: make(map[string]*nodeState), now: time.Now}
}

// OnDelta registers the sink for closed deltas. Set once at wiring time
func (a *Aggregator) OnDelta(fn func(donorID string, at time.Time, bytes uint64)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onDelta = fn
}

// Ingest folds one sample in
func (a *Aggregator) Ingest(s Sample) {
	if s.At.IsZero() {
		s.At = a.now()
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	state, ok := a.nodes[s.NodeID]
	if !ok {
		state = &nodeState{}
		if from, seeded := a.seed[s.NodeID]; seeded {
			state.totalUp, state.totalDown, state.totalProbe = from.Up, from.Down, from.Probe
			delete(a.seed, s.NodeID)
		}
		a.nodes[s.NodeID] = state
	}
	state.donorID = s.DonorID
	state.sessions = s.ActiveSessions
	state.streams = s.ActiveStreams

	rebase := state.bootID != s.BootID || s.UpBytes < state.up || s.DownBytes < state.down
	if !rebase && !state.lastAt.IsZero() {
		elapsed := s.At.Sub(state.lastAt).Seconds()
		if elapsed > 0 {
			deltaUp := s.UpBytes - state.up
			deltaDown := s.DownBytes - state.down
			state.upRate = float64(deltaUp) / elapsed
			state.downRate = float64(deltaDown) / elapsed
			state.totalUp += deltaUp
			state.totalDown += deltaDown
			if s.ProbeBytes >= state.probe {
				state.totalProbe += s.ProbeBytes - state.probe
			}
			a.lifetime += deltaUp + deltaDown
			if a.onDelta != nil {
				a.onDelta(s.DonorID, s.At, deltaUp+deltaDown)
			}
		}
	} else {
		state.upRate, state.downRate = 0, 0
	}
	state.bootID = s.BootID
	state.up, state.down = s.UpBytes, s.DownBytes
	state.probe = s.ProbeBytes
	state.lastAt = s.At
}

// Forget drops a node, so a removed donor stops showing up in the totals.
//
// The lifetime figure deliberately keeps what that node carried: the traffic
// happened, and a counter that shrinks when a donor leaves would tell visitors
// the federation had done less work than it had
func (a *Aggregator) Forget(nodeID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.nodes, nodeID)
}

// LoadLifetime seeds the lifetime counter from whatever was persisted, so a
// restart of the head does not reset the public total to zero
func (a *Aggregator) LoadLifetime(bytes uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if bytes > a.lifetime {
		a.lifetime = bytes
	}
}

// LoadPeriodBase ставит отметку начала периода
func (a *Aggregator) LoadPeriodBase(bytes uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if bytes > a.periodBase {
		a.periodBase = bytes
	}
}

// PeriodBase - сохраняемая отметка
func (a *Aggregator) PeriodBase() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.periodBase
}

// StartPeriod открывает новый период от текущего итога
func (a *Aggregator) StartPeriod() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.periodBase = a.lifetime
}

// Lifetime is the persistable total
func (a *Aggregator) Lifetime() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lifetime
}

// Global is the federation-wide view
func (a *Aggregator) Global() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	snap := Snapshot{At: now, LifetimeBytes: a.lifetime}
	seen := make(map[string]bool, len(a.nodes)+len(a.shared))
	for id := range a.nodes {
		seen[id] = true
	}
	for id := range a.shared {
		seen[id] = true
	}
	snap.NodesTotal = len(seen)
	// Период считается от сохранённой отметки, а не суммой счётчиков в памяти:
	// иначе выкат башки показывает ноль там, где трафик был
	if a.lifetime > a.periodBase {
		snap.PeriodBytes = a.lifetime - a.periodBase
	}
	for _, n := range a.nodes {
		snap.UpBytes += n.totalUp
		snap.DownBytes += n.totalDown
		snap.ProbeBytes += n.totalProbe
		if now.Sub(n.lastAt) > staleAfter {
			continue
		}
		snap.NodesOnline++
		snap.Sessions += n.sessions
		snap.Streams += n.streams
		snap.UpRateBps += n.upRate
		snap.DownRateBps += n.downRate
	}
	// Ноды соседней реплики: без них лендинг показывает то весь флот, то его
	// половину, смотря кому достался запрос
	for id, n := range a.shared {
		// Свою ноду знаем точнее из памяти: она обновляется каждым сэмплом, а
		// не раз в тик, и посчитать её дважды значит удвоить весь флот
		if _, ours := a.nodes[id]; ours {
			continue
		}
		snap.UpBytes += n.Up
		snap.DownBytes += n.Down
		snap.ProbeBytes += n.Probe
		if now.Sub(n.At) > staleAfter+sharedLag {
			continue
		}
		snap.NodesOnline++
		snap.Sessions += n.Sessions
		snap.Streams += n.Streams
		snap.UpRateBps += n.UpRate
		snap.DownRateBps += n.DownRate
	}
	return snap
}

// Donor is one donor's aggregate view
func (a *Aggregator) Donor(donorID string) DonorSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	out := DonorSnapshot{DonorID: donorID}
	for _, n := range a.nodes {
		if n.donorID != donorID {
			continue
		}
		out.Nodes++
		out.UpBytes += n.totalUp
		out.DownBytes += n.totalDown
		out.ProbeBytes += n.totalProbe
		if now.Sub(n.lastAt) > staleAfter {
			continue
		}
		out.NodesOnline++
		out.Sessions += n.sessions
		out.UpRateBps += n.upRate
		out.DownRateBps += n.downRate
	}
	for id, n := range a.shared {
		if _, ours := a.nodes[id]; ours {
			continue
		}
		if n.DonorID != donorID {
			continue
		}
		out.Nodes++
		out.UpBytes += n.Up
		out.DownBytes += n.Down
		out.ProbeBytes += n.Probe
		if now.Sub(n.At) > staleAfter+sharedLag {
			continue
		}
		out.NodesOnline++
		out.Sessions += n.Sessions
		out.UpRateBps += n.UpRate
		out.DownRateBps += n.DownRate
	}
	return out
}

// Donors lists every donor with nodes, for an operator overview
func (a *Aggregator) Donors() []string {
	a.mu.Lock()
	seen := make(map[string]bool, len(a.nodes)+len(a.shared))
	for _, n := range a.nodes {
		if n.donorID != "" {
			seen[n.donorID] = true
		}
	}
	for _, n := range a.shared {
		if n.DonorID != "" {
			seen[n.DonorID] = true
		}
	}
	a.mu.Unlock()
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
