// Package registry keeps what the head knows about donated nodes: their
// passports, the budget their donor pledged, and the rotation state that decides
// whether they are handed out. M0 keeps it in memory; the store interface is here
// so persistence lands without touching callers
package registry

import (
	"errors"
	"log"
	"sort"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// ErrUnknownNode is returned for a node id the registry has never enrolled
// ErrEmptyBudget refuses a pledge of zero: a node with no budget cannot be
// scheduled, and silently accepting it would look like a node that simply
// stopped working.
var ErrEmptyBudget = errors.New("registry: a node needs a non-zero monthly budget")

var ErrUnknownNode = errors.New("registry: unknown node")

// Node is the head's view of one donated machine
type Node struct {
	ID          string
	Fingerprint string
	Secret      string
	DonorID     string
	Passport    *fedpb.NodePassport

	DeclaredBudgetBytes uint64
	OfferedPorts        []uint32
	// BehindProxy: перед нодой стоит прокси, отдающий адрес клиента заголовком
	// PROXY protocol. Инбаунды такой ноды должны его принимать, иначе она видит
	// адрес прокси вместо человека
	BehindProxy bool
	// PublicPort - порт прокси, куда стучится клиент. Уходит в ссылки вместо
	// того, что слушает Xray
	PublicPort uint32
	// XrayVersion и VktpVersion - сборки, которые нода реально несёт: то, что
	// оператор выбрал, и то, что доехало, это разные вещи
	XrayVersion string
	VktpVersion string
	// RelayEndpoint - куда приложение набирает VK TURN на этой ноде
	RelayEndpoint string
	// RealityDest - чью tls-личность нода заимствует. Хранится, а не считается
	// на лету: вычисление по пулу меняет ответ при каждом изменении пула, а
	// dest уходит в выданные ссылки как SNI - сменился, и каждая из них мертва
	RealityDest string

	State  fedpb.RotationState
	Reason string

	// BootID and the counters below come from the agent's cumulative samples. A
	// changed BootID means the node restarted and its counters went back to zero,
	// so the next sample must re-baseline instead of being billed as a delta -
	// otherwise a reboot silently refunds the traffic the donor already spent
	BootID        string
	LastUpBytes   uint64
	LastDownBytes uint64
	UsedBytes     uint64
	// ProbeBytes - сколько из UsedBytes сожгли зонды. Донору это всё равно
	// считается, но он вправе видеть, что часть трафика - наши проверки
	LastProbeBytes uint64
	ProbeBytes     uint64

	// PeriodStart anchors the donor's monthly pledge. Usage is billed against it
	// and reset when the calendar month rolls, because a budget nobody resets is
	// a budget that parks the whole fleet forever
	PeriodStart time.Time

	Health   Health
	Sessions uint32

	// Reachability is what probes inside the censored network measured, keyed by
	// address and transport. It is the only trustworthy statement about whether a
	// node is usable: a node can be perfectly healthy from the head's own network
	// and completely unreachable from where the users are
	Reachability map[string]Reachability

	// RealityPublicKey and Mldsa65Verify are the public halves the node reported
	// after applying a config. Only these travel; the private halves are minted
	// on the node and never leave it. Without them the head cannot build a link
	RealityPublicKey string
	Mldsa65Verify    string

	ConfigVersion uint64
	JoinedAt      time.Time
	LastSeen      time.Time
}

// Health is what the node last said about itself. Self-reported and therefore
// only good for scheduling, never for anything a donor could be paid on
type Health struct {
	// CPUPct is smoothed, because one busy second is not a reason to move
	// somebody's traffic to another machine
	CPUPct    float64
	Uptime    uint64
	XrayState string
	VktpState string
	At        time.Time
}

// Reachability is one probe's measurement of one address over one transport.
//
// Throughput, not just success: nodes are far more often shaped than blocked, so
// a handshake check reports a healthy node while the user gets kilobytes a second
type Reachability struct {
	Address     string
	Transport   string
	OK          bool
	HandshakeMs uint32
	RTTMs       uint32
	DownloadBps uint64
	Error       string
	ProbeID     string
	At          time.Time
}

// ReachKey is how a measurement is filed
func ReachKey(address, transport string) string { return address + "|" + transport }

// cpuSmoothing weights the newest sample. Low enough to ignore a spike, high
// enough to react inside a minute at a five second heartbeat
const cpuSmoothing = 0.3

// BudgetUsedFraction is how much of the pledge is spent. Above one when a donor
// overshot, which the scoring has to survive rather than clamp away silently
func (n *Node) BudgetUsedFraction() float64 {
	if n.DeclaredBudgetBytes == 0 {
		return 0
	}
	return float64(n.UsedBytes) / float64(n.DeclaredBudgetBytes)
}

// Online reports whether the node has reported recently enough to be trusted as
// live. Assignment treats a stale node as unusable regardless of its score
func (n *Node) Online(now time.Time, within time.Duration) bool {
	return !n.LastSeen.IsZero() && now.Sub(n.LastSeen) <= within
}

// Registry is a concurrency-safe set of nodes
type Registry struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	now   func() time.Time
	store Store
}

// New builds an empty registry that forgets everything on restart. Only for
// tests: a real head must use Open
func New() *Registry {
	return &Registry{nodes: make(map[string]*Node), now: time.Now, store: nopStore{}}
}

// SetNow overrides the clock. Only tests have any business calling it; a fleet
// whose clock can be moved from outside is a fleet whose budgets can be
func (r *Registry) SetNow(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

// Open builds a registry backed by store and loads whatever it already holds
func Open(store Store) (*Registry, error) {
	r := &Registry{nodes: make(map[string]*Node), now: time.Now, store: store}
	nodes, err := store.Load()
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		r.nodes[n.ID] = n
	}
	return r, nil
}

// persistLocked writes the fleet out. Callers hold the lock
func (r *Registry) persistLocked() {
	nodes := make([]*Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		nodes = append(nodes, n)
	}
	if err := r.store.Save(nodes); err != nil {
		log.Printf("registry: persist: %v", err)
	}
}

// Add stores a freshly enrolled node, replacing any earlier enrollment with the
// same fingerprint so a re-run of the installer does not fork a node's identity
func (r *Registry) Add(n *Node) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, existing := range r.nodes {
		if existing.Fingerprint != "" && existing.Fingerprint == n.Fingerprint {
			delete(r.nodes, id)
		}
	}
	n.JoinedAt = r.now()
	r.nodes[n.ID] = n
	r.persistLocked()
}

// Get returns a copy-free handle to a node. Callers must not mutate it outside
// the registry's own methods
func (r *Registry) Get(id string) (*Node, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.nodes[id]
	if !ok {
		return nil, ErrUnknownNode
	}
	return n, nil
}

// Authenticate resolves a node by id and checks the secret it presented
func (r *Registry) Authenticate(id, secret string) (*Node, error) {
	n, err := r.Get(id)
	if err != nil {
		return nil, err
	}
	if secret == "" || n.Secret != secret {
		return nil, errors.New("registry: node secret mismatch")
	}
	return n, nil
}

// List returns every node, newest enrollment last
func (r *Registry) List() []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		out = append(out, n)
	}
	return out
}

// Touch records that the node reported, keeping it out of the stale bucket
func (r *Registry) Touch(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.nodes[id]; ok {
		n.LastSeen = r.now()
	}
}

// ApplyHeartbeat records what the node says about itself
func (r *Registry) ApplyHeartbeat(id string, cpuPct float64, uptime uint64, xrayState, vktpState string) error {
	return r.applyHeartbeat(id, cpuPct, uptime, xrayState, vktpState, "", "")
}

// ApplyHeartbeatWithBuilds принимает и версии сборок, которые нода реально несёт
func (r *Registry) ApplyHeartbeatWithBuilds(id string, cpuPct float64, uptime uint64,
	xrayState, vktpState, xrayVersion, vktpVersion string) error {
	return r.applyHeartbeat(id, cpuPct, uptime, xrayState, vktpState, xrayVersion, vktpVersion)
}

// SetRelayEndpoint запоминает, куда приложение набирает VK TURN на этой ноде
func (r *Registry) SetRelayEndpoint(id, endpoint string) {
	if endpoint == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if node, ok := r.nodes[id]; ok && node.RelayEndpoint != endpoint {
		node.RelayEndpoint = endpoint
		r.persistLocked()
	}
}

func (r *Registry) applyHeartbeat(id string, cpuPct float64, uptime uint64,
	xrayState, vktpState, xrayVersion, vktpVersion string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return ErrUnknownNode
	}
	now := r.now()
	n.LastSeen = now
	if n.Health.At.IsZero() {
		n.Health.CPUPct = cpuPct
	} else {
		n.Health.CPUPct = cpuSmoothing*cpuPct + (1-cpuSmoothing)*n.Health.CPUPct
	}
	n.Health.Uptime, n.Health.XrayState, n.Health.VktpState, n.Health.At = uptime, xrayState, vktpState, now
	if xrayVersion != "" {
		n.XrayVersion = xrayVersion
	}
	if vktpVersion != "" {
		n.VktpVersion = vktpVersion
	}
	return nil
}

// ApplyProbeReport files what a vantage point measured
func (r *Registry) ApplyProbeReport(nodeID string, reach Reachability) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[nodeID]
	if !ok {
		return ErrUnknownNode
	}
	if reach.At.IsZero() {
		reach.At = r.now()
	}
	if n.Reachability == nil {
		n.Reachability = map[string]Reachability{}
	}
	n.Reachability[ReachKey(reach.Address, reach.Transport)] = reach
	// Probe results decide what gets handed out, so losing them on restart would
	// leave the head with no verified address for anybody. They arrive minutes
	// apart, so writing on each one costs nothing
	r.persistLocked()
	return nil
}

// VerifiedAddresses lists the addresses a probe has recently carried traffic
// over. An address nobody has reached is a candidate, never a verified route
func (n *Node) VerifiedAddresses(now time.Time, within time.Duration) []string {
	seen := map[string]bool{}
	var out []string
	for _, reach := range n.Reachability {
		if !reach.OK || now.Sub(reach.At) > within {
			continue
		}
		if seen[reach.Address] {
			continue
		}
		seen[reach.Address] = true
		out = append(out, reach.Address)
	}
	sort.Strings(out)
	return out
}

// WorkingTransports lists the transports that recently carried traffic. Kept
// separate from the address because tcp and xhttp are blocked independently, so
// a node usually loses one and keeps the other rather than dying outright
func (n *Node) WorkingTransports(now time.Time, within time.Duration) []string {
	seen := map[string]bool{}
	var out []string
	for _, reach := range n.Reachability {
		if !reach.OK || now.Sub(reach.At) > within || seen[reach.Transport] {
			continue
		}
		seen[reach.Transport] = true
		out = append(out, reach.Transport)
	}
	sort.Strings(out)
	return out
}

// BestRTT is the lowest recent round trip measured to this node, and whether any
// measurement exists at all
func (n *Node) BestRTT(now time.Time, within time.Duration) (uint32, bool) {
	best := uint32(0)
	found := false
	for _, reach := range n.Reachability {
		if !reach.OK || reach.RTTMs == 0 || now.Sub(reach.At) > within {
			continue
		}
		if !found || reach.RTTMs < best {
			best, found = reach.RTTMs, true
		}
	}
	return best, found
}

// SetIdentity records the public halves of the node's inbound identity
func (r *Registry) SetIdentity(id, realityPublicKey, mldsa65Verify string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return ErrUnknownNode
	}
	if realityPublicKey == "" || (n.RealityPublicKey == realityPublicKey && n.Mldsa65Verify == mldsa65Verify) {
		return nil
	}
	n.RealityPublicKey, n.Mldsa65Verify = realityPublicKey, mldsa65Verify
	r.persistLocked()
	return nil
}

// SetPassport обновляет паспорт ноды и выбрасывает замеры по адресам, которых в
// нём больше нет: провайдер переносит сервер, а старый адрес остаётся в отчётах
// и выглядит рабочим маршрутом
func (r *Registry) SetPassport(id string, passport *fedpb.NodePassport) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	node, ok := r.nodes[id]
	if !ok {
		return ErrUnknownNode
	}
	node.Passport = passport
	known := map[string]bool{}
	for _, addr := range passport.GetAddresses() {
		known[addr.GetAddress()] = true
	}
	for key, reach := range node.Reachability {
		if !known[reach.Address] {
			delete(node.Reachability, key)
		}
	}
	r.persistLocked()
	return nil
}

// SetDest pins which borrowed identity a node presents.
//
// Written once and then left alone: the dest goes into every link handed out as
// the SNI, so recomputing it - which is what a pool-size-dependent hash does the
// moment the pool changes - would silently break every client already using it.
func (r *Registry) SetDest(id, dest string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return ErrUnknownNode
	}
	if dest == "" || n.RealityDest == dest {
		return nil
	}
	n.RealityDest = dest
	r.persistLocked()
	return nil
}

// SetBudget changes what a donor has pledged for the month.
//
// It exists because the pledge was fixed at enrolment, and a donor who wanted to
// give more had to re-enrol the node - throwing away its identity, its probe
// results and the traffic already counted against the period.
//
// Lowering it below what the node has already carried is allowed on purpose: the
// donor is saying "stop here", and the rotation reads used against declared, so
// the node drains and parks by itself instead of needing a separate off switch.
func (r *Registry) SetBudget(id string, budgetBytes uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return ErrUnknownNode
	}
	if budgetBytes == 0 {
		return ErrEmptyBudget
	}
	if n.DeclaredBudgetBytes == budgetBytes {
		return nil
	}
	n.DeclaredBudgetBytes = budgetBytes
	r.persistLocked()
	return nil
}

// SetSessions records how many clients the node is carrying
func (r *Registry) SetSessions(id string, sessions uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.nodes[id]; ok {
		n.Sessions = sessions
	}
}

// rollPeriodLocked resets a donor's spend when the calendar month turns. Without
// it the first node to exhaust its pledge stays parked forever, which looks
// exactly like a broken federation
func (r *Registry) rollPeriodLocked(n *Node, now time.Time) bool {
	if n.PeriodStart.IsZero() {
		n.PeriodStart = monthStart(now)
		return false
	}
	current := monthStart(now)
	if !current.After(n.PeriodStart) {
		return false
	}
	n.PeriodStart = current
	n.UsedBytes = 0
	n.ProbeBytes = 0
	return true
}

func monthStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}

// RollPeriods resets every node whose month has turned, and reports which ones
// so the caller can bring them back out of budget parking
func (r *Registry) RollPeriods() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var rolled []string
	for id, n := range r.nodes {
		if r.rollPeriodLocked(n, now) {
			rolled = append(rolled, id)
		}
	}
	if len(rolled) > 0 {
		sort.Strings(rolled)
		r.persistLocked()
	}
	return rolled
}

// ApplySample folds a cumulative stats sample into the node's usage.
//
// Deltas are derived here rather than sent by the agent so a dropped sample is
// harmless. A counter that moved backwards, or a sample carrying a different
// boot id, means the node restarted: re-baseline and bill nothing for that step
func (r *Registry) ApplySample(id, bootID string, up, down, probe uint64) (billed uint64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return 0, ErrUnknownNode
	}
	now := r.now()
	n.LastSeen = now
	r.rollPeriodLocked(n, now)
	rebase := n.BootID != bootID || up < n.LastUpBytes || down < n.LastDownBytes
	if !rebase {
		gross := (up - n.LastUpBytes) + (down - n.LastDownBytes)
		var probed uint64
		if probe >= n.LastProbeBytes {
			probed = probe - n.LastProbeBytes
			n.ProbeBytes += probed
		}
		// Замеры зондов гоняем МЫ САМИ, и писать их в бюджет донора это уже
		// свинство: он обещал трафик людям, а не нашей ебле с диагностикой.
		// Считаются отдельно и из счёта вычитаются
		billed = gross
		if billed > probed {
			billed -= probed
		} else {
			billed = 0
		}
		n.UsedBytes += billed
	}
	n.BootID = bootID
	n.LastUpBytes = up
	n.LastDownBytes = down
	n.LastProbeBytes = probe
	// Counters are only flushed when something was actually billed: persisting on
	// every 1 Hz sample from every node would hammer the disk for nothing
	if billed > 0 {
		r.persistLocked()
	}
	return billed, nil
}

// SetState moves a node between rotation states
func (r *Registry) SetState(id string, state fedpb.RotationState, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return ErrUnknownNode
	}
	n.State = state
	n.Reason = reason
	r.persistLocked()
	return nil
}

// Remove выкидывает ноду из реестра.
//
// Донор вправе забрать свою машину когда захочет и без объяснений: федерация
// держится на добровольности, а удерживать чужое железо это уже наглость
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.nodes[id]; !ok {
		return ErrUnknownNode
	}
	delete(r.nodes, id)
	r.persistLocked()
	return nil
}
