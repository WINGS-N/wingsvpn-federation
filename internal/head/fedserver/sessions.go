package fedserver

import (
	"errors"
	"log"
	"strings"
	"sync"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// outboundDepth bounds what can be queued for one node. Small: everything on
// this path is a command, and a backlog of stale commands is worse than an error
// that says the node is not keeping up
const outboundDepth = 16

var (
	// ErrNotConnected means the node has no open session, which is a normal
	// state for a machine that is rebooting, not an error to shout about
	ErrNotConnected = errors.New("fedserver: node has no open session")
	// ErrBacklogged means the node is connected but not draining its commands
	ErrBacklogged = errors.New("fedserver: node is not keeping up with commands")
)

// session is one agent's open stream, owned by the goroutine serving it
type session struct {
	out  chan *fedpb.HeadFrame
	done chan struct{}
	once sync.Once
}

func newSession() *session {
	return &session{out: make(chan *fedpb.HeadFrame, outboundDepth), done: make(chan struct{})}
}

// send queues a frame without blocking the caller. Commands are never dropped
// silently: a full queue is reported, because a node that missed a profile
// removal is a node still serving somebody who was cut off
func (s *session) send(frame *fedpb.HeadFrame) error {
	select {
	case <-s.done:
		return ErrNotConnected
	default:
	}
	select {
	case s.out <- frame:
		return nil
	case <-s.done:
		return ErrNotConnected
	default:
		return ErrBacklogged
	}
}

func (s *session) close() { s.once.Do(func() { close(s.done) }) }

func (s *Server) register(nodeID string) *session {
	sess := newSession()
	s.mu.Lock()
	if existing, ok := s.sessions[nodeID]; ok {
		// A node that reconnected before the head noticed the old stream died.
		// The newest stream is the live one
		existing.close()
	}
	s.sessions[nodeID] = sess
	s.mu.Unlock()
	return sess
}

func (s *Server) deregister(nodeID string, sess *session) {
	s.mu.Lock()
	if current, ok := s.sessions[nodeID]; ok && current == sess {
		delete(s.sessions, nodeID)
	}
	s.mu.Unlock()
	sess.close()
}

func (s *Server) sessionFor(nodeID string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[nodeID]
	return sess, ok
}

// Connected lists the nodes with an open session
func (s *Server) Connected() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		out = append(out, id)
	}
	return out
}

// Push sends one frame to one node
func (s *Server) Push(nodeID string, frame *fedpb.HeadFrame) error {
	sess, ok := s.sessionFor(nodeID)
	if !ok {
		return ErrNotConnected
	}
	return sess.send(frame)
}

// PushProfiles adds and removes users on a live node
func (s *Server) PushProfiles(nodeID string, add []*fedpb.ProfileSpec, remove []string) error {
	return s.PushProfilesAndPeers(nodeID, add, remove, nil)
}

// PushProfilesAndPeers - то же самое плюс отзыв пиров VK TURN.
//
// Пиры живут в релее, а не в ядре, поэтому снятие профиля их не касается: без
// этого карантин остаётся бумажным, и отрезанный человек продолжает возить
// трафик по уже выданному ключу
func (s *Server) PushProfilesAndPeers(nodeID string, add []*fedpb.ProfileSpec, remove, peers []string) error {
	if len(add) == 0 && len(remove) == 0 && len(peers) == 0 {
		return nil
	}
	return s.Push(nodeID, &fedpb.HeadFrame{Frame: &fedpb.HeadFrame_ProfileDelta{
		ProfileDelta: &fedpb.ProfileDelta{
			Add: add, RemoveProfileIds: remove, RemovePeerKeys: peers,
		},
	}})
}

// PushRotation tells a node what its rotation state should be
func (s *Server) PushRotation(nodeID string, state fedpb.RotationState, reason string) error {
	return s.Push(nodeID, &fedpb.HeadFrame{Frame: &fedpb.HeadFrame_Rotation{
		Rotation: &fedpb.RotationCommand{State: state, Reason: reason},
	}})
}

// Upgrade tells nodes to fetch a build, or just to restart what they run.
//
// An empty nodeID means the whole fleet. Nodes that are not connected right now
// are simply skipped rather than queued: the config they pull on their next
// hello already carries the fleet's chosen build, so a node that was offline
// during the command catches up by reconnecting, not by replaying it.
func (s *Server) Upgrade(nodeID, component, version, url, sha512 string, restartOnly bool) int {
	frame := &fedpb.HeadFrame{Frame: &fedpb.HeadFrame_Upgrade{Upgrade: &fedpb.UpgradeCommand{
		Component:   component,
		Version:     version,
		Url:         url,
		Sha512:      sha512,
		RestartOnly: restartOnly,
	}}}

	targets := []string{nodeID}
	if strings.TrimSpace(nodeID) == "" {
		targets = s.Connected()
	}
	sent := 0
	for _, id := range targets {
		if err := s.Push(id, frame); err != nil {
			log.Printf("fedserver: %s on %s: %v", component, id, err)
			continue
		}
		sent++
	}
	return sent
}

// PushPeerLimits ставит потолки скорости пирам VK TURN. Режет их ядро ноды:
// своего ограничителя у релея нет
func (s *Server) PushPeerLimits(nodeID string, limits []*fedpb.PeerLimit) error {
	if len(limits) == 0 {
		return nil
	}
	return s.Push(nodeID, &fedpb.HeadFrame{Frame: &fedpb.HeadFrame_ProfileDelta{
		ProfileDelta: &fedpb.ProfileDelta{PeerLimits: limits},
	}})
}
