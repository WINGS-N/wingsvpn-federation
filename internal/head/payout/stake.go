package payout

import (
	"errors"
	"sync"
	"time"
)

// Payouts stay off until an operator turns them on. Separate from the federation
// toggle on purpose: a federation can run for months donating capacity with no
// money anywhere near it, and that is the default
var ErrPayoutsDisabled = errors.New("payout: payouts are disabled")

// Switch gates everything that moves money
type Switch struct {
	mu      sync.RWMutex
	enabled bool
}

// NewSwitch starts disabled
func NewSwitch() *Switch { return &Switch{} }

// Enabled reports whether money may move
func (s *Switch) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// Set turns payouts on or off
func (s *Switch) Set(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = on
}

// Stake is a donor's deposit, held against the possibility that they lie.
//
// Held by us rather than on a chain: a contract cannot see whether a node
// cheated, so the verdict would come from the head anyway. Keeping the deposit
// here loses nothing real and avoids publishing who is in the paid tier
type Stake struct {
	DonorID   string
	Amount    Micro
	PostedAt  time.Time
	Slashed   Micro
	SlashedAt time.Time
	Reason    string
}

// Available is what is left to slash
func (s *Stake) Available() Micro {
	if s.Slashed >= s.Amount {
		return 0
	}
	return s.Amount - s.Slashed
}

var (
	// ErrNoStake means the donor never posted a deposit
	ErrNoStake = errors.New("payout: donor has no stake")
	// ErrStakeExhausted means there is nothing left to take
	ErrStakeExhausted = errors.New("payout: stake already exhausted")
)

// Stakes holds deposits
type Stakes struct {
	mu     sync.Mutex
	stakes map[string]*Stake
	now    func() time.Time
}

// NewStakes builds an empty set
func NewStakes() *Stakes {
	return &Stakes{stakes: make(map[string]*Stake), now: time.Now}
}

// Post records a deposit, adding to whatever the donor already staked
func (s *Stakes) Post(donorID string, amount Micro) *Stake {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.stakes[donorID]
	if !ok {
		existing = &Stake{DonorID: donorID, PostedAt: s.now()}
		s.stakes[donorID] = existing
	}
	existing.Amount += amount
	return existing
}

// Get returns a donor's stake
func (s *Stakes) Get(donorID string) (*Stake, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.stakes[donorID]
	return st, ok
}

// Slash takes part of a deposit. Capped at what remains rather than erroring on
// overflow: a verdict should not fail to apply because it asked for more than
// was there
func (s *Stakes) Slash(donorID string, amount Micro, reason string) (Micro, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.stakes[donorID]
	if !ok {
		return 0, ErrNoStake
	}
	available := st.Available()
	if available == 0 {
		return 0, ErrStakeExhausted
	}
	taken := amount
	if taken > available {
		taken = available
	}
	st.Slashed += taken
	st.SlashedAt = s.now()
	st.Reason = reason
	return taken, nil
}
