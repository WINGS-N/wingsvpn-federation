// Package tokens mints and burns the enroll tokens an installer presents
package tokens

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	// ErrUnknown covers a token that never existed, was already redeemed or
	// expired. The caller must not distinguish these to the network: telling an
	// attacker which of the three it was hands them an oracle
	ErrUnknown = errors.New("tokens: rejected")
)

type entry struct {
	donorID   string
	expiresAt time.Time
	usedAt    time.Time
	// remaining joins this token still authorises. One is the ordinary case;
	// more is a donor enrolling a fleet from one Secret, which is what a
	// DaemonSet does.
	remaining uint32
}

// Backend хранит выданные токены. Без него башка теряет их при выкате, и
// установщик, скопированный минуту назад, перестаёт работать
type Backend interface {
	Put(token, donorID string, expiresAt time.Time, remaining uint32) error
	Take(token string, now time.Time) (string, error)
	Left(token string, now time.Time) uint32
}

// Store keeps enroll tokens
type Store struct {
	mu      sync.Mutex
	byHash  map[string]*entry
	now     func() time.Time
	backend Backend
}

// New builds an empty store
func New() *Store {
	return &Store{byHash: make(map[string]*entry), now: time.Now}
}

// SetBackend переводит хранение в базу
func (s *Store) SetBackend(b Backend) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backend = b
}

// Mint issues a single-use token for a donor. The raw value is returned once and
// never stored in the clear
func (s *Store) Mint(donorID string, ttl time.Duration) (string, error) {
	return s.MintFor(donorID, ttl, 1)
}

// MintFor issues a token good for uses joins.
//
// More than one is for a donor bringing a fleet: a DaemonSet enrols on every
// host it lands on out of a single Secret, and one token per host would mean one
// release per host. The trade is written down plainly: a token good for n joins
// is a token n strangers could use if it leaks, bounded by n and by the ttl.
func (s *Store) MintFor(donorID string, ttl time.Duration, uses uint32) (string, error) {
	if uses == 0 {
		uses = 1
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	expires := s.now().Add(ttl)
	if s.backend != nil {
		if err := s.backend.Put(token, donorID, expires, uses); err != nil {
			return "", err
		}
		return token, nil
	}
	s.byHash[token] = &entry{donorID: donorID, expiresAt: expires, remaining: uses}
	return token, nil
}

// Redeem consumes one of a token's uses
func (s *Store) Redeem(token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backend != nil {
		return s.backend.Take(token, s.now())
	}
	e, ok := s.byHash[token]
	if !ok || e.remaining == 0 || s.now().After(e.expiresAt) {
		return "", ErrUnknown
	}
	e.remaining--
	e.usedAt = s.now()
	return e.donorID, nil
}

// Remaining is how many joins a token still authorises, for an operator asking
// how much of a fleet token is left. An unknown token reads as zero, the same as
// a spent one, so this cannot be used to probe for valid tokens.
func (s *Store) Remaining(token string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backend != nil {
		return s.backend.Left(token, s.now())
	}
	e, ok := s.byHash[token]
	if !ok || s.now().After(e.expiresAt) {
		return 0
	}
	return e.remaining
}
