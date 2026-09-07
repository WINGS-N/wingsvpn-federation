// Package assign scores donated nodes and decides which ones a free user gets.
//
// The scoring exists to spend a donor's pledge evenly rather than as fast as
// possible: a node with a terabyte a month that burned half of it in three days
// has to shed load on its own, or the federation is empty for the rest of the
// month
package assign

import (
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
)

// Options tunes scoring and rotation without a rebuild
type Options struct {
	// MaxSessions is what one node is assumed to carry comfortably. A passport
	// field would be better; until a node reports one, an assumption beats
	// pretending capacity is unlimited
	MaxSessions uint32
	// FreshWithin is how recently a node must have reported to be handed out at
	// all. A node whose numbers are stale is a node nobody can reason about
	FreshWithin time.Duration
	// MissedBeatsPark is how long silence lasts before the node is parked
	MissedBeatsPark time.Duration
	// TopK bounds the pool a pick is drawn from, so the best node does not take
	// every new user and immediately stop being the best
	TopK int
	// ProbeValidFor is how long a measurement stands for. Beyond it the address
	// counts as unproven again: a route that worked last week says nothing about
	// a route being blocked today
	ProbeValidFor time.Duration
	// RequireProbe refuses any node no probe has confirmed. Off by default so a
	// federation with no vantage point still works; the head turns it on once a
	// probe is actually reporting, because until then it would park the fleet
	RequireProbe bool
}

// DefaultOptions is a starting point, not a truth
func DefaultOptions() Options {
	return Options{
		MaxSessions:     200,
		FreshWithin:     15 * time.Second,
		MissedBeatsPark: 15 * time.Second,
		TopK:            8,
		ProbeValidFor:   30 * time.Minute,
	}
}

func (o Options) withDefaults() Options {
	d := DefaultOptions()
	if o.MaxSessions == 0 {
		o.MaxSessions = d.MaxSessions
	}
	if o.FreshWithin == 0 {
		o.FreshWithin = d.FreshWithin
	}
	if o.MissedBeatsPark == 0 {
		o.MissedBeatsPark = d.MissedBeatsPark
	}
	if o.TopK == 0 {
		o.TopK = d.TopK
	}
	if o.ProbeValidFor == 0 {
		o.ProbeValidFor = d.ProbeValidFor
	}
	return o
}

// Score is a node's rank plus the parts it was built from, so a scheduling
// decision can be explained instead of shrugged at
type Score struct {
	Total    float64
	Headroom float64
	Pace     float64
	Health   float64
	Capacity float64
	Fresh    bool
}

// Weights of the four terms. Headroom dominates because the pledge is the
// binding constraint: everything else only matters among nodes that can still
// afford to carry traffic
const (
	weightHeadroom = 0.40
	weightPace     = 0.25
	weightHealth   = 0.20
	weightCapacity = 0.15
)

// paceFloor keeps the first hours of a period from projecting a whole month's
// spend off a few minutes of traffic and parking a healthy node
const paceFloor = 6 * time.Hour

// uptimeFull is the uptime at which that term saturates. A month of continuous
// service is as much as it is worth crediting
const uptimeFull = 30 * 24 * time.Hour

// ScoreNode ranks one node
func ScoreNode(n *registry.Node, now time.Time, opts Options) Score {
	opts = opts.withDefaults()
	s := Score{
		Headroom: headroom(n),
		Pace:     pace(n, now),
		Health:   health(n, now, opts.ProbeValidFor),
		Capacity: capacity(n, opts.MaxSessions),
		Fresh:    !n.LastSeen.IsZero() && now.Sub(n.LastSeen) <= opts.FreshWithin,
	}
	if !s.Fresh {
		return s
	}
	s.Total = weightHeadroom*s.Headroom + weightPace*s.Pace +
		weightHealth*s.Health + weightCapacity*s.Capacity
	return s
}

func headroom(n *registry.Node) float64 {
	if n.DeclaredBudgetBytes == 0 {
		return 0
	}
	return clamp(1-n.BudgetUsedFraction(), 0, 1)
}

// pace projects the period's spend from what has been used so far. This is the
// whole burn-rate defence: no separate rule, just a term that falls as a node
// runs ahead of its own budget
func pace(n *registry.Node, now time.Time) float64 {
	if n.DeclaredBudgetBytes == 0 || n.PeriodStart.IsZero() {
		return 0
	}
	elapsed := now.Sub(n.PeriodStart)
	if elapsed < paceFloor {
		elapsed = paceFloor
	}
	periodLength := periodLengthOf(n.PeriodStart)
	if elapsed > periodLength {
		elapsed = periodLength
	}
	projected := n.BudgetUsedFraction() * float64(periodLength) / float64(elapsed)
	return 1 - clamp(projected, 0, 2)/2
}

func periodLengthOf(start time.Time) time.Duration {
	next := start.AddDate(0, 1, 0)
	return next.Sub(start)
}

// rttFloor and rttCeiling bracket the round trip a probe measured. Below the
// floor a node is as good as it gets; above the ceiling it is unpleasant however
// healthy the machine itself is
const (
	rttFloor   = 40
	rttCeiling = 400
)

// health mixes what the node says about itself with what a probe measured from
// where the users are. The probe half is the honest one: a node can report a
// bored CPU and still be unusable from inside the censored network
func health(n *registry.Node, now time.Time, probeValidFor time.Duration) float64 {
	uptime := clamp(float64(n.Health.Uptime)/uptimeFull.Seconds(), 0, 1)
	cpu := clamp(n.Health.CPUPct/100, 0, 1)
	self := 0.6*uptime + 0.4*(1-cpu)
	if n.Health.At.IsZero() {
		// Never reported: not evidence of health, and not evidence of trouble
		self = 0.5
	}

	rtt, measured := n.BestRTT(now, probeValidFor)
	if !measured {
		// No vantage point has reached this node. Scoring it as if the network
		// were perfect would be a guess dressed up as a measurement
		return self
	}
	latency := 1 - clamp((float64(rtt)-rttFloor)/(rttCeiling-rttFloor), 0, 1)
	return 0.6*self + 0.4*latency
}

func capacity(n *registry.Node, maxSessions uint32) float64 {
	if maxSessions == 0 {
		return 0
	}
	return 1 - clamp(float64(n.Sessions)/float64(maxSessions), 0, 1)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Rotation thresholds. Draining keeps existing clients working and only stops
// new ones, because cutting a live connection to protect a budget costs the user
// far more than it saves the donor
const (
	drainScore         = 0.25
	drainBudgetFrac    = 0.85
	parkBudgetFrac     = 0.97
	quarantineIsManual = true
)

// NextState is what the node's rotation state should become
func NextState(n *registry.Node, score Score, now time.Time, opts Options) (fedpb.RotationState, string) {
	opts = opts.withDefaults()
	// Quarantine is a judgement, not a measurement: it is entered by hand or by
	// the oracle and never left by arithmetic
	if quarantineIsManual && n.State == fedpb.RotationState_ROTATION_STATE_QUARANTINED {
		return n.State, n.Reason
	}
	if n.LastSeen.IsZero() || now.Sub(n.LastSeen) > opts.MissedBeatsPark {
		return fedpb.RotationState_ROTATION_STATE_PARKED, "no heartbeat"
	}
	used := n.BudgetUsedFraction()
	switch {
	case used >= parkBudgetFrac:
		return fedpb.RotationState_ROTATION_STATE_PARKED, "monthly budget spent"
	case used >= drainBudgetFrac:
		return fedpb.RotationState_ROTATION_STATE_DRAINING, "approaching the monthly budget"
	case score.Total < drainScore:
		return fedpb.RotationState_ROTATION_STATE_DRAINING, "score below the draining threshold"
	default:
		return fedpb.RotationState_ROTATION_STATE_ACTIVE, ""
	}
}
