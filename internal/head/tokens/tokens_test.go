package tokens

import (
	"testing"
	"time"
)

func TestRedeemOnlyOnce(t *testing.T) {
	s := New()
	token, err := s.Mint("donor-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	donor, err := s.Redeem(token)
	if err != nil {
		t.Fatalf("first redeem failed: %v", err)
	}
	if donor != "donor-1" {
		t.Errorf("donor = %q, want donor-1", donor)
	}
	if _, err := s.Redeem(token); err != ErrUnknown {
		t.Errorf("second redeem = %v, want ErrUnknown", err)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	s := New()
	now := time.Now()
	s.now = func() time.Time { return now }
	token, err := s.Mint("donor-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := s.Redeem(token); err != ErrUnknown {
		t.Errorf("expired redeem = %v, want ErrUnknown", err)
	}
}

func TestUnknownTokenIsRejected(t *testing.T) {
	s := New()
	if _, err := s.Redeem("never-minted"); err != ErrUnknown {
		t.Errorf("err = %v, want ErrUnknown", err)
	}
	if _, err := s.Redeem(""); err != ErrUnknown {
		t.Errorf("empty token accepted")
	}
}

// Every rejection must look the same on the wire: telling an attacker whether a
// token was unknown, spent or expired hands them an oracle
func TestRejectionsAreIndistinguishable(t *testing.T) {
	s := New()
	now := time.Now()
	s.now = func() time.Time { return now }
	spent, _ := s.Mint("d", time.Hour)
	_, _ = s.Redeem(spent)
	expired, _ := s.Mint("d", time.Minute)
	s.now = func() time.Time { return now.Add(2 * time.Minute) }

	for name, token := range map[string]string{"unknown": "nope", "spent": spent, "expired": expired} {
		if _, err := s.Redeem(token); err != ErrUnknown {
			t.Errorf("%s: err = %v, want the same ErrUnknown as every other rejection", name, err)
		}
	}
}

func TestCompoundRoundTrip(t *testing.T) {
	joined := JoinCompound("fleet-secret", "donor-token")
	fleet, token, err := SplitCompound(joined)
	if err != nil {
		t.Fatal(err)
	}
	if fleet != "fleet-secret" || token != "donor-token" {
		t.Errorf("split = %q / %q", fleet, token)
	}
}

// The fleet secret is hex and may itself contain no separator, but a caller can
// still hand us junk; every malformed shape must fail rather than half-parse
func TestCompoundRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", ".", "noseparator", ".leading", "trailing."} {
		if _, _, err := SplitCompound(bad); err == nil {
			t.Errorf("SplitCompound(%q) should have failed", bad)
		}
	}
}

// A secret containing dots must still split at the last one, so the token half
// is never truncated
func TestCompoundSplitsAtTheLastSeparator(t *testing.T) {
	fleet, token, err := SplitCompound("a.b.c.tok")
	if err != nil {
		t.Fatal(err)
	}
	if fleet != "a.b.c" || token != "tok" {
		t.Errorf("split = %q / %q, want a.b.c / tok", fleet, token)
	}
}

// A fleet token is what a DaemonSet enrols on: one Secret, one token, a join per
// host. It must stop dead on the last one.
func TestAFleetTokenIsGoodForExactlyItsUses(t *testing.T) {
	s := New()
	token, err := s.MintFor("donor", time.Hour, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := s.Redeem(token); err != nil {
			t.Fatalf("join %d was refused: %v", i, err)
		}
		if got, want := s.Remaining(token), uint32(3-i); got != want {
			t.Errorf("after join %d Remaining = %d, want %d", i, got, want)
		}
	}
	if _, err := s.Redeem(token); err == nil {
		t.Fatal("a fourth join was allowed on a token good for three")
	}
}

// Zero uses is what an old caller sends, and it must not mean a token nobody can
// redeem - nor one anybody can redeem for ever.
func TestZeroUsesMeansOne(t *testing.T) {
	s := New()
	token, err := s.MintFor("donor", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(token); err != nil {
		t.Fatalf("the first join was refused: %v", err)
	}
	if _, err := s.Redeem(token); err == nil {
		t.Fatal("a second join was allowed on a single-use token")
	}
}

// Expiry outranks the counter: uses left is no reason to accept a stale token.
func TestUsesLeftDoNotOutliveTheTtl(t *testing.T) {
	s := New()
	now := time.Now()
	s.now = func() time.Time { return now }
	token, err := s.MintFor("donor", time.Minute, 5)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Redeem(token); err == nil {
		t.Fatal("an expired token was redeemed because it had uses left")
	}
	if got := s.Remaining(token); got != 0 {
		t.Errorf("Remaining = %d on an expired token, want 0", got)
	}
}
