package payout

import (
	"errors"
	"testing"
	"time"
)

// A real Solana address, used only as a well-formed value
const goodAddress = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"

type fakeSettler struct {
	calls int
	ref   string
	err   error
}

func (f *fakeSettler) Settle(*Payout) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.ref, nil
}

func period() (time.Time, time.Time) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}

func seeded(t *testing.T) (*Ledger, time.Time, time.Time) {
	t.Helper()
	l := NewLedger()
	l.Switch().Set(true)
	if err := l.SetAddress("donor-1", goodAddress); err != nil {
		t.Fatal(err)
	}
	start, end := period()
	l.Accrue(Accrual{DonorID: "donor-1", PeriodStart: start, PeriodEnd: end, Amount: 1_500_000})
	l.Accrue(Accrual{DonorID: "donor-1", PeriodStart: start, PeriodEnd: end, Amount: 2_250_000})
	return l, start, end
}

func TestApproveSumsThePeriod(t *testing.T) {
	l, start, end := seeded(t)
	p, err := l.Approve("donor-1", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if p.Amount != 3_750_000 {
		t.Errorf("amount = %d, want 3750000", p.Amount)
	}
	if got := p.Amount.FormatUSDT(); got != "3.750000" {
		t.Errorf("formatted = %q", got)
	}
}

// The whole reason the id is derived rather than random: a retry must find the
// same payout instead of creating a second one for the same period
func TestApproveIsIdempotent(t *testing.T) {
	l, start, end := seeded(t)
	first, err := l.Approve("donor-1", start, end)
	if err != nil {
		t.Fatal(err)
	}
	second, err := l.Approve("donor-1", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Errorf("two approvals produced different ids: %q and %q", first.ID, second.ID)
	}
	if len(l.Pending()) != 1 {
		t.Errorf("pending = %d, want a single payout", len(l.Pending()))
	}
}

// The one that matters: a second settle must not send money again
func TestSettleOnlyOnce(t *testing.T) {
	l, start, end := seeded(t)
	p, err := l.Approve("donor-1", start, end)
	if err != nil {
		t.Fatal(err)
	}
	settler := &fakeSettler{ref: "sig-1"}
	if _, err := l.Settle(p.ID, settler); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Settle(p.ID, settler); !errors.Is(err, ErrAlreadySettled) {
		t.Errorf("second settle = %v, want ErrAlreadySettled", err)
	}
	if settler.calls != 1 {
		t.Errorf("the settler was called %d times, so a retry would have paid twice", settler.calls)
	}
}

// A settler that failed must leave the payout unsettled and retryable, not
// half-recorded
func TestFailedSettlementStaysPending(t *testing.T) {
	l, start, end := seeded(t)
	p, _ := l.Approve("donor-1", start, end)
	failing := &fakeSettler{err: errors.New("rpc down")}
	if _, err := l.Settle(p.ID, failing); err == nil {
		t.Fatal("a failed settlement was reported as success")
	}
	if p.Settled() {
		t.Error("a failed settlement marked the payout as paid")
	}
	if len(l.Pending()) != 1 {
		t.Error("a failed payout dropped out of the pending list")
	}
	ok := &fakeSettler{ref: "sig-2"}
	if _, err := l.Settle(p.ID, ok); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if p.Reference != "sig-2" {
		t.Errorf("reference = %q", p.Reference)
	}
}

func TestApproveRefusesWithoutAddress(t *testing.T) {
	l := NewLedger()
	start, end := period()
	l.Accrue(Accrual{DonorID: "nobody", PeriodStart: start, PeriodEnd: end, Amount: 1})
	if _, err := l.Approve("nobody", start, end); !errors.Is(err, ErrNoAddress) {
		t.Errorf("err = %v, want ErrNoAddress", err)
	}
}

func TestApproveRefusesEmptyPeriod(t *testing.T) {
	l := NewLedger()
	if err := l.SetAddress("donor-1", goodAddress); err != nil {
		t.Fatal(err)
	}
	start, end := period()
	if _, err := l.Approve("donor-1", start, end); !errors.Is(err, ErrNothingAccrued) {
		t.Errorf("err = %v, want ErrNothingAccrued", err)
	}
}

// Accruals outside the window must not leak into the payout
func TestApproveIgnoresOtherPeriods(t *testing.T) {
	l, start, end := seeded(t)
	l.Accrue(Accrual{
		DonorID:     "donor-1",
		PeriodStart: start.AddDate(0, -1, 0),
		PeriodEnd:   start,
		Amount:      9_000_000,
	})
	p, err := l.Approve("donor-1", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if p.Amount != 3_750_000 {
		t.Errorf("amount = %d, an accrual from another period leaked in", p.Amount)
	}
}

// A typo in an address means the money leaves and never arrives, so it is
// checked at entry rather than at settlement
func TestAddressValidation(t *testing.T) {
	if err := ValidateSolanaAddress(goodAddress); err != nil {
		t.Errorf("a valid address was rejected: %v", err)
	}
	bad := map[string]string{
		"empty":      "",
		"not base58": "0OIl-not-valid",
		"too short":  "9WzDXwBbmkg8",
		"ethereum":   "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
	}
	for name, addr := range bad {
		if err := ValidateSolanaAddress(addr); err == nil {
			t.Errorf("%s: %q was accepted", name, addr)
		}
	}
	l := NewLedger()
	if err := l.SetAddress("d", "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"); err == nil {
		t.Error("an ethereum address was stored as a solana payout address")
	}
}

// Amounts are integer minor units end to end: a float would quietly round
// somebody's payout
func TestFormatDoesNotLoseMinorUnits(t *testing.T) {
	cases := map[Micro]string{
		0:         "0.000000",
		1:         "0.000001",
		999_999:   "0.999999",
		1_000_000: "1.000000",
		1_000_001: "1.000001",
	}
	for amount, want := range cases {
		if got := amount.FormatUSDT(); got != want {
			t.Errorf("%d formatted as %q, want %q", amount, got, want)
		}
	}
}
