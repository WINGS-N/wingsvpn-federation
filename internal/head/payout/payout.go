// Package payout keeps the accrual ledger donors are paid from.
//
// The ledger is authoritative off-chain and a chain is only a settlement layer
// on top. Built that way round because the evidence a payout rests on - verified
// uptime, probe results, signed client receipts - lives here, and because a chain
// that disagrees with the ledger is a dispute rather than a source of truth
package payout

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// USDT on Solana carries six decimals. Amounts are integer minor units
// everywhere: floats would round somebody's payout and nobody would notice
const usdtDecimals = 6

// Micro is one millionth of a USDT, the unit the whole package counts in
type Micro uint64

// FormatUSDT renders an amount for humans without going through a float
func (m Micro) FormatUSDT() string {
	whole := uint64(m) / 1_000_000
	frac := uint64(m) % 1_000_000
	return fmt.Sprintf("%d.%0*d", whole, usdtDecimals, frac)
}

var (
	// ErrAlreadySettled means this payout was already paid. Returned rather than
	// silently succeeding so a retry cannot double-pay
	ErrAlreadySettled = errors.New("payout: already settled")
	// ErrUnknownPayout covers an id the ledger never issued
	ErrUnknownPayout = errors.New("payout: unknown")
	// ErrNoAddress means the donor has no payout address on file
	ErrNoAddress = errors.New("payout: donor has no payout address")
	// ErrNothingAccrued means there is nothing to pay for that period
	ErrNothingAccrued = errors.New("payout: nothing accrued")
)

// Basis records why a donor earned something, so a disputed payout can be
// answered with evidence rather than an assertion
type Basis struct {
	VerifiedHours    float64
	ProbeChecksOK    uint32
	ProbeChecksTotal uint32
	// ReceiptBytes is what clients actually signed for. Node self-reported
	// volume never appears here: it is the number the donor could inflate
	ReceiptBytes uint64
}

// Accrual is one period's earning for one donor
type Accrual struct {
	DonorID     string
	PeriodStart time.Time
	PeriodEnd   time.Time
	Amount      Micro
	Basis       Basis
}

// Payout is an accrual approved for settlement
type Payout struct {
	// ID doubles as the idempotency key. Derived from donor and period so the
	// same period can never be paid twice even across a head restart
	ID          string
	DonorID     string
	Address     string
	Amount      Micro
	PeriodStart time.Time
	PeriodEnd   time.Time

	SettledAt time.Time
	// Reference is whatever the settler returned, a transaction signature for a
	// chain. Kept so a donor can check the payment themselves
	Reference string
}

// Settled reports whether this payout has been paid
func (p *Payout) Settled() bool { return !p.SettledAt.IsZero() }

// Settler moves money. A chain implementation lands behind this later; the
// ledger neither knows nor cares which one
type Settler interface {
	// Settle must be idempotent on ref: called twice with the same payout it
	// must not send twice
	Settle(p *Payout) (ref string, err error)
}

// Ledger holds accruals and payouts
type Ledger struct {
	mu        sync.Mutex
	addresses map[string]string
	accruals  map[string][]Accrual
	payouts   map[string]*Payout
	now       func() time.Time
	gate      *Switch
}

// NewLedger builds an empty ledger with payouts disabled
func NewLedger() *Ledger {
	return NewLedgerWithSwitch(NewSwitch())
}

// NewLedgerWithSwitch builds a ledger gated by an existing switch
func NewLedgerWithSwitch(gate *Switch) *Ledger {
	return &Ledger{
		addresses: make(map[string]string),
		accruals:  make(map[string][]Accrual),
		payouts:   make(map[string]*Payout),
		now:       time.Now,
		gate:      gate,
	}
}

// Switch exposes the gate so an operator can flip it
func (l *Ledger) Switch() *Switch { return l.gate }

// SetAddress records where a donor is paid, rejecting anything that is not a
// usable Solana account
func (l *Ledger) SetAddress(donorID, address string) error {
	if err := ValidateSolanaAddress(address); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addresses[donorID] = address
	return nil
}

// Address returns the donor's payout address
func (l *Ledger) Address(donorID string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	addr, ok := l.addresses[donorID]
	return addr, ok
}

// Accrue records an earning
func (l *Ledger) Accrue(a Accrual) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accruals[a.DonorID] = append(l.accruals[a.DonorID], a)
}

// payoutID ties a payout to exactly one donor and period, which is what makes a
// retry safe: the second attempt finds the existing record instead of creating
// a new one
func payoutID(donorID string, periodStart, periodEnd time.Time) string {
	return fmt.Sprintf("%s:%d-%d", donorID, periodStart.Unix(), periodEnd.Unix())
}

// Approve turns everything accrued in a period into one payout, ready to settle
func (l *Ledger) Approve(donorID string, periodStart, periodEnd time.Time) (*Payout, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	addr, ok := l.addresses[donorID]
	if !ok || addr == "" {
		return nil, ErrNoAddress
	}
	id := payoutID(donorID, periodStart, periodEnd)
	if existing, ok := l.payouts[id]; ok {
		return existing, nil
	}
	var total Micro
	for _, a := range l.accruals[donorID] {
		if a.PeriodStart.Before(periodStart) || a.PeriodEnd.After(periodEnd) {
			continue
		}
		total += a.Amount
	}
	if total == 0 {
		return nil, ErrNothingAccrued
	}
	p := &Payout{
		ID:          id,
		DonorID:     donorID,
		Address:     addr,
		Amount:      total,
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}
	l.payouts[id] = p
	return p, nil
}

// Settle pays an approved payout exactly once
func (l *Ledger) Settle(id string, settler Settler) (*Payout, error) {
	l.mu.Lock()
	p, ok := l.payouts[id]
	l.mu.Unlock()
	if !ok {
		return nil, ErrUnknownPayout
	}
	if p.Settled() {
		return p, ErrAlreadySettled
	}
	// Gated here rather than at accrual: recording what a donor earned is useful
	// even with payouts off, but nothing may actually move
	if !l.gate.Enabled() {
		return nil, ErrPayoutsDisabled
	}
	ref, err := settler.Settle(p)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Re-check under the lock: two callers racing on the same payout must not
	// both record a settlement
	if p.Settled() {
		return p, ErrAlreadySettled
	}
	p.SettledAt = l.now()
	p.Reference = ref
	return p, nil
}

// Pending lists approved but unsettled payouts, oldest first
func (l *Ledger) Pending() []*Payout {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*Payout
	for _, p := range l.payouts {
		if !p.Settled() {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeriodEnd.Before(out[j].PeriodEnd) })
	return out
}

// base58Alphabet is Bitcoin's, which Solana also uses
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ValidateSolanaAddress checks that the string decodes to a 32 byte account.
// Worth doing at entry: a typo here means the payout leaves and never arrives
func ValidateSolanaAddress(address string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return ErrNoAddress
	}
	decoded, err := base58Decode(address)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return fmt.Errorf("payout: address decodes to %d bytes, want 32", len(decoded))
	}
	return nil
}

// DecodeBase58 разбирает адрес Solana. Экспортирован, потому что тот же разбор
// нужен цепочке, а два декодера в одном репозитории однажды разъедутся нахуй
func DecodeBase58(s string) ([]byte, error) { return base58Decode(s) }

func base58Decode(s string) ([]byte, error) {
	num := []byte{0}
	for _, r := range s {
		idx := strings.IndexRune(base58Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("payout: %q is not base58", string(r))
		}
		carry := idx
		for i := len(num) - 1; i >= 0; i-- {
			carry += int(num[i]) * 58
			num[i] = byte(carry % 256)
			carry /= 256
		}
		for carry > 0 {
			num = append([]byte{byte(carry % 256)}, num...)
			carry /= 256
		}
	}
	// Leading '1' characters encode leading zero bytes
	var leading int
	for _, r := range s {
		if r != '1' {
			break
		}
		leading++
	}
	for len(num) > 1 && num[0] == 0 {
		num = num[1:]
	}
	return append(make([]byte, leading), num...), nil
}
