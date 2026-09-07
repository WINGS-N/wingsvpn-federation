package oracle

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

type forgetfulSink struct {
	signals []Signal
	forgot  int
}

func (f *forgetfulSink) Signal(s Signal) error            { f.signals = append(f.signals, s); return nil }
func (f *forgetfulSink) Decision(Verdict) error           { return nil }
func (f *forgetfulSink) Load(time.Time) ([]Signal, error) { return nil, nil }
func (f *forgetfulSink) ForgetSignals(string, fedpb.AbuseKind, time.Time, time.Time) error {
	f.forgot++
	return nil
}

// Расписка, доехавшая из очереди, доказывает ровно то, за отсутствие чего
// наказали: минус за то окно обязан уйти вместе с хранилищем
func TestForgiveDropsTheAccusationForThatWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sink := &forgetfulSink{}
	j := NewJudge(NewRulesScorer())
	j.SetNow(func() time.Time { return now })
	j.SetSink(sink)

	inside := Signal{ClientID: "user-1", Kind: fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS, Count: 5, Observed: now.Add(-time.Hour)}
	outside := Signal{ClientID: "user-1", Kind: fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS, Count: 5, Observed: now.Add(-10 * time.Hour)}
	other := Signal{ClientID: "user-1", Kind: fedpb.AbuseKind_ABUSE_KIND_ADDRESS_MISMATCH, Count: 1, Observed: now.Add(-time.Hour)}
	j.Observe(inside)
	j.Observe(outside)
	j.Observe(other)

	forgiven := j.Forgive("user-1", fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS, now.Add(-2*time.Hour), now.Add(-30*time.Minute))
	if forgiven != 1 {
		t.Fatalf("прощено %d обвинений, ждали одно", forgiven)
	}
	if sink.forgot != 1 {
		t.Fatalf("хранилище не почищено: %d", sink.forgot)
	}

	left := j.Features("user-1")
	if len(left) != 2 {
		t.Fatalf("осталось %d сигналов, ждали два", len(left))
	}
	for _, s := range left {
		if s.Kind == fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS && s.Observed.Equal(inside.Observed) {
			t.Fatal("прощённое обвинение осталось")
		}
	}
}

// Чужое окно и чужой вид не трогаем: амнистия закрывает ровно то, что доказано
func TestForgiveLeavesEverythingElseAlone(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	j := NewJudge(NewRulesScorer())
	j.SetNow(func() time.Time { return now })
	j.Observe(Signal{ClientID: "user-1", Kind: fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS, Observed: now.Add(-time.Hour)})

	if got := j.Forgive("user-2", fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS, now.Add(-2*time.Hour), now); got != 0 {
		t.Fatalf("прощено чужое: %d", got)
	}
	if got := j.Forgive("user-1", fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS, now, now); got != 0 {
		t.Fatalf("пустое окно что-то простило: %d", got)
	}
	if len(j.Features("user-1")) != 1 {
		t.Fatal("сигнал пропал без причины")
	}
}
