// Package probes drives the vantage points.
//
// A node is measured from inside the censored network, not from the head's own
// machine, because those are different questions: a node can answer the head
// perfectly and be shaped down to kilobytes where the users actually are. That
// is why the measurement is a download and not a ping
package probes

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/profiles"
	"wingsnet.org/federation/internal/head/registry"
)

// probeUser is the pseudo-user probe profiles are issued to. It never
// corresponds to a person, which is the point: a vantage point is a machine we
// do not fully control, and a real user's credential must never sit on one
const probeUser = "__probe__"

// DefaultInterval - как часто точка наблюдения перемеряет ноду. Реже, чем
// хочется: круг с несколькими целями качает реальные мегабайты через чужой
// сервер, и частая проверка сама становится нагрузкой
const DefaultInterval = 15 * time.Minute

// DefaultDownloadBytes - сколько тянет один замер. Меньше четырёх мегабайт TCP
// не успевает разогнаться, и канал выглядит медленнее, чем он есть
const DefaultDownloadBytes = 4 << 20

// DefaultDownloadURL is what the probe fetches through the tunnel
const DefaultDownloadURL = "https://speed.cloudflare.com/__down?bytes=2097152"

// Pusher places the probe's own profile on a node
type Pusher interface {
	PushProfiles(nodeID string, add []*fedpb.ProfileSpec, remove []string) error
}

// Fleet keeps one profile per node for the probes to measure through
type Fleet struct {
	reg    *registry.Registry
	push   Pusher
	config func(nodeID string) *fedpb.NodeConfig

	downloadURL   string
	downloadBytes uint32
	interval      time.Duration
	now           func() time.Time

	mu sync.Mutex
	// byNode is the probe's credential on each node. One stable profile per node
	// rather than one per check: minting and revoking on somebody else's server
	// every few minutes is a lot of churn to buy nothing, since a dedicated probe
	// credential already carries no user's identity
	byNode map[string]profiles.Profile
}

// New builds a probe fleet over the head's registry
func New(reg *registry.Registry, push Pusher, config func(nodeID string) *fedpb.NodeConfig) *Fleet {
	return &Fleet{
		reg:           reg,
		push:          push,
		config:        config,
		downloadURL:   DefaultDownloadURL,
		downloadBytes: DefaultDownloadBytes,
		interval:      DefaultInterval,
		now:           time.Now,
		byNode:        map[string]profiles.Profile{},
	}
}

// SpecsFor is the probe's profile on one node. It is merged into what the head
// reconciles a reconnecting node against, or the reconcile would delete the very
// credential the measurements run through
func (f *Fleet) SpecsFor(nodeID string) []*fedpb.ProfileSpec {
	f.mu.Lock()
	p, ok := f.byNode[nodeID]
	f.mu.Unlock()
	if !ok {
		return nil
	}
	return f.specs(p, nodeID)
}

// specs - профиль зонда со снятой пометкой учёта.
//
// Снимать её надо в КАЖДОМ месте, где спеки уезжают на ноду: сверка при
// переподключении перезаписывает профиль, и стоит ей отдать спеки без этого,
// как наши собственные замеры начинают считаться трафиком донора
func (f *Fleet) specs(p profiles.Profile, nodeID string) []*fedpb.ProfileSpec {
	specs := p.Specs(f.config(nodeID))
	for _, spec := range specs {
		// Не наш это трафик донора, а наши замеры: выставлять их ему счётом
		// было бы свинством
		spec.Metered = false
	}
	return specs
}

// ensureProfile mints the probe's credential on a node once
func (f *Fleet) ensureProfile(nodeID string) (profiles.Profile, bool) {
	f.mu.Lock()
	if p, ok := f.byNode[nodeID]; ok {
		f.mu.Unlock()
		return p, true
	}
	f.mu.Unlock()

	p, err := profiles.Issue(probeUser, nodeID, f.now(), 0)
	if err != nil {
		return profiles.Profile{}, false
	}
	specs := f.specs(p, nodeID)
	if err := f.push.PushProfiles(nodeID, specs, nil); err != nil {
		log.Printf("probes: could not place the probe profile on %s: %v", nodeID, err)
		return profiles.Profile{}, false
	}
	f.mu.Lock()
	f.byNode[nodeID] = p
	f.mu.Unlock()
	return p, true
}

// Targets is what a vantage point should measure next
func (f *Fleet) Targets() *fedpb.ProbeTask {
	task := &fedpb.ProbeTask{IntervalSeconds: uint32(f.interval.Seconds())}
	now := f.now()
	for _, n := range f.reg.List() {
		// A quarantined node is not measured: it is not going to be handed out
		// whatever the numbers say, and measuring it costs a donor real traffic
		if n.State == fedpb.RotationState_ROTATION_STATE_QUARANTINED {
			continue
		}
		if n.RealityPublicKey == "" || !n.Online(now, 2*time.Minute) {
			continue
		}
		p, ok := f.ensureProfile(n.ID)
		if !ok {
			continue
		}
		// Per node: a host that could not take 443 is measured on the port it
		// actually serves, not on the one the fleet defaults to
		cfg := f.config(n.ID)
		if cfg == nil {
			continue
		}
		for _, addr := range candidateAddresses(n) {
			for _, in := range cfg.GetInbounds() {
				if !in.GetReality() {
					continue
				}
				task.Targets = append(task.Targets, &fedpb.ProbeTarget{
					NodeId:           n.ID,
					Transport:        networkOf(in),
					Host:             addr,
					Port:             reachablePort(n, in),
					Uuid:             p.UUID,
					Flow:             in.GetFlow(),
					RealityPublicKey: n.RealityPublicKey,
					Mldsa65Verify:    postQuantumVerify(cfg, n),
					ServerName:       firstOr(cfg.GetReality().GetServerNames(), ""),
					ShortId:          firstOr(cfg.GetReality().GetShortIds(), ""),
					XhttpPath:        pathOf(in),
					DownloadBytes:    f.downloadBytes,
					DownloadUrl:      f.downloadURL,
				})
			}
		}
	}
	return task
}

// Ingest files a measurement against the node it was taken on
func (f *Fleet) Ingest(probeID string, report *fedpb.ProbeReport) {
	measured := time.Unix(report.GetMeasuredUnix(), 0)
	if report.GetMeasuredUnix() == 0 {
		measured = f.now()
	}
	err := f.reg.ApplyProbeReport(report.GetNodeId(), registry.Reachability{
		Address:     report.GetAddress(),
		Transport:   report.GetTransport(),
		OK:          report.GetHandshakeOk(),
		HandshakeMs: report.GetHandshakeMs(),
		RTTMs:       report.GetRttMs(),
		DownloadBps: report.GetDownloadBps(),
		Error:       report.GetError(),
		ProbeID:     probeID,
		At:          measured,
	})
	if err != nil {
		log.Printf("probes: report for unknown node %s", report.GetNodeId())
	}
}

// candidateAddresses is every address worth trying: self-reported and pinned
// alike. Which of them actually works is exactly what the probe decides
func candidateAddresses(n *registry.Node) []string {
	seen := map[string]bool{}
	var v4, v6 []string
	for _, addr := range n.Passport.GetAddresses() {
		host := addr.GetAddress()
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		if isIPv6(host) {
			v6 = append(v6, host)
			continue
		}
		v4 = append(v4, host)
	}
	// IPv4 первым: до подавляющего большинства людей дотягивается только он, а
	// IPv6 идёт бонусом, который у самой точки наблюдения может отсутствовать
	return append(v4, v6...)
}

// reachablePort - порт, на который клиент реально приходит. За прокси Xray
// слушает локально, а снаружи открыт порт прокси, и замер по локальному порту
// уходит в таймаут вместо ответа
func reachablePort(_ *registry.Node, in *fedpb.InboundSpec) uint32 {
	if port := in.GetPublicPort(); port != 0 {
		return port
	}
	return in.GetPort()
}

func isIPv6(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addr := net.ParseIP(strings.Trim(host, "[]"))
	return addr != nil && addr.To4() == nil
}

// postQuantumVerify hands the probe the verify half only when the node is
// actually signing with it. Measuring with the wrong expectation reports a
// perfectly good node as unreachable
func postQuantumVerify(cfg *fedpb.NodeConfig, n *registry.Node) string {
	if !cfg.GetReality().GetPostQuantum() {
		return ""
	}
	return n.Mldsa65Verify
}

func networkOf(in *fedpb.InboundSpec) string {
	if n := in.GetNetwork(); n != "" {
		return n
	}
	return "tcp"
}

func pathOf(in *fedpb.InboundSpec) string {
	if p := in.GetXhttp().GetPath(); p != "" {
		return p
	}
	return "/"
}

func firstOr(values []string, fallback string) string {
	if len(values) > 0 {
		return values[0]
	}
	return fallback
}
