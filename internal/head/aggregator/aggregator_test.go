package aggregator

import (
	"testing"
	"time"
)

func fixedAgg(t *testing.T, now *time.Time) *Aggregator {
	t.Helper()
	a := New()
	a.now = func() time.Time { return *now }
	return a
}

func TestRateComesFromTheDelta(t *testing.T) {
	now := time.Now()
	a := fixedAgg(t, &now)
	a.Ingest(Sample{NodeID: "n1", DonorID: "d1", BootID: "b", UpBytes: 0, DownBytes: 0, At: now})
	a.Ingest(Sample{NodeID: "n1", DonorID: "d1", BootID: "b", UpBytes: 1000, DownBytes: 4000, At: now.Add(time.Second)})

	now = now.Add(time.Second)
	snap := a.Global()
	if snap.UpRateBps != 1000 || snap.DownRateBps != 4000 {
		t.Errorf("rates = %.0f/%.0f, want 1000/4000", snap.UpRateBps, snap.DownRateBps)
	}
	if snap.UpBytes != 1000 || snap.DownBytes != 4000 {
		t.Errorf("totals = %d/%d", snap.UpBytes, snap.DownBytes)
	}
}

// A node reboot resets its counters. Counting that as a delta would invent a
// huge spike, and treating it as negative would corrupt the totals
func TestRebootDoesNotSpikeTheRate(t *testing.T) {
	now := time.Now()
	a := fixedAgg(t, &now)
	a.Ingest(Sample{NodeID: "n1", BootID: "b1", UpBytes: 5_000_000, DownBytes: 5_000_000, At: now})
	now = now.Add(time.Second)
	a.Ingest(Sample{NodeID: "n1", BootID: "b2", UpBytes: 10, DownBytes: 10, At: now})

	snap := a.Global()
	if snap.UpRateBps != 0 || snap.DownRateBps != 0 {
		t.Errorf("a reboot produced rates %.0f/%.0f, want zero", snap.UpRateBps, snap.DownRateBps)
	}

	// And accounting continues from the new baseline
	now = now.Add(time.Second)
	a.Ingest(Sample{NodeID: "n1", BootID: "b2", UpBytes: 110, DownBytes: 10, At: now})
	if snap := a.Global(); snap.UpRateBps != 100 {
		t.Errorf("post-reboot rate = %.0f, want 100", snap.UpRateBps)
	}
}

// A node that went quiet must stop contributing to the live speed, or the
// counter keeps showing traffic that is not happening
func TestStaleNodeStopsCountingTowardsRate(t *testing.T) {
	now := time.Now()
	a := fixedAgg(t, &now)
	a.Ingest(Sample{NodeID: "n1", BootID: "b", UpBytes: 0, At: now})
	a.Ingest(Sample{NodeID: "n1", BootID: "b", UpBytes: 1000, At: now.Add(time.Second)})
	now = now.Add(time.Second)
	if snap := a.Global(); snap.NodesOnline != 1 || snap.UpRateBps == 0 {
		t.Fatalf("setup: online=%d rate=%.0f", snap.NodesOnline, snap.UpRateBps)
	}

	now = now.Add(staleAfter + time.Second)
	snap := a.Global()
	if snap.NodesOnline != 0 {
		t.Errorf("online = %d, want the silent node dropped", snap.NodesOnline)
	}
	if snap.UpRateBps != 0 {
		t.Errorf("rate = %.0f, a silent node is still counted as moving traffic", snap.UpRateBps)
	}
	// Its historical bytes stay: they did happen
	if snap.UpBytes != 1000 {
		t.Errorf("total = %d, want the past traffic kept", snap.UpBytes)
	}
}

func TestGlobalSumsAcrossNodes(t *testing.T) {
	now := time.Now()
	a := fixedAgg(t, &now)
	for _, id := range []string{"n1", "n2", "n3"} {
		a.Ingest(Sample{NodeID: id, BootID: "b", UpBytes: 0, At: now})
		a.Ingest(Sample{NodeID: id, BootID: "b", UpBytes: 500, ActiveSessions: 2, At: now.Add(time.Second)})
	}
	now = now.Add(time.Second)
	snap := a.Global()
	if snap.NodesOnline != 3 {
		t.Errorf("online = %d", snap.NodesOnline)
	}
	if snap.Sessions != 6 {
		t.Errorf("sessions = %d, want 6", snap.Sessions)
	}
	if snap.UpRateBps != 1500 {
		t.Errorf("rate = %.0f, want 1500", snap.UpRateBps)
	}
}

// A donor sees their own nodes only, and only as aggregates
func TestDonorViewIsScopedAndAggregate(t *testing.T) {
	now := time.Now()
	a := fixedAgg(t, &now)
	a.Ingest(Sample{NodeID: "n1", DonorID: "d1", BootID: "b", At: now})
	a.Ingest(Sample{NodeID: "n1", DonorID: "d1", BootID: "b", UpBytes: 100, ActiveSessions: 3, At: now.Add(time.Second)})
	a.Ingest(Sample{NodeID: "n2", DonorID: "d2", BootID: "b", At: now})
	a.Ingest(Sample{NodeID: "n2", DonorID: "d2", BootID: "b", UpBytes: 900, ActiveSessions: 7, At: now.Add(time.Second)})
	now = now.Add(time.Second)

	d1 := a.Donor("d1")
	if d1.Nodes != 1 || d1.Sessions != 3 || d1.UpBytes != 100 {
		t.Errorf("d1 = %+v, want only their own node", d1)
	}
	if d1.UpRateBps != 100 {
		t.Errorf("d1 rate = %.0f", d1.UpRateBps)
	}
	if donors := a.Donors(); len(donors) != 2 {
		t.Errorf("donors = %v", donors)
	}
}

// Removing a node must take it out of the totals, or a departed donor keeps
// inflating the public counter forever
func TestForgetRemovesFromTotals(t *testing.T) {
	now := time.Now()
	a := fixedAgg(t, &now)
	a.Ingest(Sample{NodeID: "n1", BootID: "b", At: now})
	a.Ingest(Sample{NodeID: "n1", BootID: "b", UpBytes: 1000, At: now.Add(time.Second)})
	now = now.Add(time.Second)
	a.Forget("n1")
	snap := a.Global()
	if snap.NodesTotal != 0 || snap.UpBytes != 0 {
		t.Errorf("snapshot = %+v after forgetting the only node", snap)
	}
}
