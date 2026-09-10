// Package rotation keeps every node's state in step with what it is actually
// doing: spending its donor's pledge, answering heartbeats, carrying load.
//
// It runs on a timer rather than reacting to each sample because the decision is
// about a trend, not an event, and because a node flapping between states would
// restart its inbounds over and over
package rotation

import (
	"context"
	"errors"
	"log"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/assign"
	"wingsnet.org/federation/internal/head/fedserver"
	"wingsnet.org/federation/internal/head/registry"
)

// Pusher is how a decision reaches the node
type Pusher interface {
	PushRotation(nodeID string, state fedpb.RotationState, reason string) error
}

// DefaultInterval is how often the fleet is rescored. Ten seconds: fast enough
// that a node running away with its budget is caught in one, slow enough that
// the decision is about a trend
const DefaultInterval = 10 * time.Second

// Change is one node moving state, kept so a caller can log or test it
type Change struct {
	NodeID string
	From   fedpb.RotationState
	To     fedpb.RotationState
	Reason string
}

// Rotator moves nodes between rotation states
type Rotator struct {
	reg      *registry.Registry
	push     Pusher
	opts     assign.Options
	interval time.Duration
	now      func() time.Time
}

// New builds a rotator over the head's registry
func New(reg *registry.Registry, push Pusher, opts assign.Options) *Rotator {
	return &Rotator{reg: reg, push: push, opts: opts, interval: DefaultInterval, now: time.Now}
}

// Run rescores the fleet until ctx ends
func (r *Rotator) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, c := range r.Tick() {
				log.Printf("rotation: node %s %s -> %s (%s)", c.NodeID, name(c.From), name(c.To), c.Reason)
			}
		}
	}
}

// Tick rescores every node once and applies what changed.
//
// The monthly roll happens first: a node parked because its pledge was spent has
// to come back on its own when the month turns, or the federation empties out
// one donor at a time and never refills
func (r *Rotator) Tick() []Change {
	r.reg.RollPeriods()

	now := r.now()
	var changes []Change
	for _, n := range r.reg.List() {
		score := assign.ScoreNode(n, now, r.opts)
		next, reason := assign.NextState(n, score, now, r.opts)
		if next == n.State {
			continue
		}
		change := Change{NodeID: n.ID, From: n.State, To: next, Reason: reason}
		if err := r.reg.SetState(n.ID, next, reason); err != nil {
			log.Printf("rotation: could not set state on %s: %v", n.ID, err)
			continue
		}
		changes = append(changes, change)
		if r.push == nil {
			continue
		}
		// A node with no open session is usually a node that is down, which is
		// often why it is being parked in the first place. It picks the state up
		// from the head when it reconnects
		if err := r.push.PushRotation(n.ID, next, reason); err != nil && !errors.Is(err, fedserver.ErrNotConnected) {
			log.Printf("rotation: could not push state to %s: %v", n.ID, err)
		}
	}
	return changes
}

func name(state fedpb.RotationState) string {
	switch state {
	case fedpb.RotationState_ROTATION_STATE_ACTIVE:
		return "active"
	case fedpb.RotationState_ROTATION_STATE_DRAINING:
		return "draining"
	case fedpb.RotationState_ROTATION_STATE_PARKED:
		return "parked"
	case fedpb.RotationState_ROTATION_STATE_QUARANTINED:
		return "quarantined"
	default:
		return "unspecified"
	}
}
