package payout

import (
	"errors"
	"testing"
)

// Payouts must be off out of the box: a federation runs for months donating
// capacity with no money near it, and that is the normal case
func TestPayoutsAreDisabledByDefault(t *testing.T) {
	if NewSwitch().Enabled() {
		t.Error("payouts were enabled out of the box")
	}
	if NewLedger().Switch().Enabled() {
		t.Error("a fresh ledger came up with payouts enabled")
	}
}

// Accrual keeps running while payouts are off, only settlement is blocked:
// turning payouts on later with no history would be useless
func TestDisabledBlocksSettlementNotAccrual(t *testing.T) {
	l := NewLedger()
	if err := l.SetAddress("donor-1", goodAddress); err != nil {
		t.Fatal(err)
	}
	start, end := period()
	l.Accrue(Accrual{DonorID: "donor-1", PeriodStart: start, PeriodEnd: end, Amount: 5_000_000})

	p, err := l.Approve("donor-1", start, end)
	if err != nil {
		t.Fatalf("approval should work with payouts off: %v", err)
	}
	if p.Amount != 5_000_000 {
		t.Errorf("amount = %d", p.Amount)
	}

	settler := &fakeSettler{ref: "sig"}
	if _, err := l.Settle(p.ID, settler); !errors.Is(err, ErrPayoutsDisabled) {
		t.Errorf("settle = %v, want ErrPayoutsDisabled", err)
	}
	if settler.calls != 0 {
		t.Error("money moved while payouts were disabled")
	}

	l.Switch().Set(true)
	if _, err := l.Settle(p.ID, settler); err != nil {
		t.Fatalf("settle after enabling: %v", err)
	}
	if settler.calls != 1 {
		t.Errorf("settler calls = %d, want 1", settler.calls)
	}
}

func TestStakeAccumulates(t *testing.T) {
	s := NewStakes()
	s.Post("donor-1", 10_000_000)
	st := s.Post("donor-1", 5_000_000)
	if st.Amount != 15_000_000 {
		t.Errorf("amount = %d, want a second deposit to add", st.Amount)
	}
	if st.Available() != 15_000_000 {
		t.Errorf("available = %d", st.Available())
	}
}

// A verdict must not fail to apply because it asked for more than was left
func TestSlashCapsAtWhatRemains(t *testing.T) {
	s := NewStakes()
	s.Post("donor-1", 1_000_000)
	taken, err := s.Slash("donor-1", 4_000_000, "inflated volume")
	if err != nil {
		t.Fatal(err)
	}
	if taken != 1_000_000 {
		t.Errorf("took %d, want it capped at the 1000000 available", taken)
	}
	st, _ := s.Get("donor-1")
	if st.Available() != 0 {
		t.Errorf("available = %d, want 0", st.Available())
	}
	if st.Reason != "inflated volume" {
		t.Errorf("reason = %q, a slash must record why", st.Reason)
	}
	if _, err := s.Slash("donor-1", 1, "again"); !errors.Is(err, ErrStakeExhausted) {
		t.Errorf("err = %v, want ErrStakeExhausted", err)
	}
}

func TestSlashPartial(t *testing.T) {
	s := NewStakes()
	s.Post("donor-1", 10_000_000)
	taken, err := s.Slash("donor-1", 2_500_000, "shaped node")
	if err != nil {
		t.Fatal(err)
	}
	if taken != 2_500_000 {
		t.Errorf("took %d", taken)
	}
	st, _ := s.Get("donor-1")
	if st.Available() != 7_500_000 {
		t.Errorf("available = %d, want 7500000", st.Available())
	}
}

func TestSlashUnknownDonor(t *testing.T) {
	if _, err := NewStakes().Slash("ghost", 1, "x"); !errors.Is(err, ErrNoStake) {
		t.Errorf("err = %v, want ErrNoStake", err)
	}
}
