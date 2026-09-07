package allocator

import (
	"testing"
	"time"
)

// Нода, которой человеку не давали, в журнале не значится: по этому башка и
// отбивает чужие расписки
func TestGrantsRememberWhoHeldWhat(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	g := NewGrants()
	g.now = func() time.Time { return at }
	g.Granted("user-1", "node-a", at)

	if !g.Held("user-1", "node-a", at.Add(time.Minute)) {
		t.Fatal("свою ноду не признали")
	}
	if g.Held("user-1", "node-b", at.Add(time.Minute)) {
		t.Fatal("чужую ноду признали своей")
	}
	if g.Held("user-2", "node-a", at.Add(time.Minute)) {
		t.Fatal("ноду признали чужому человеку")
	}
}

// Снятая нода помнится ещё неделю: расписка приезжает с опозданием, и ротация
// не должна съедать чужой честный трафик
func TestRevokedNodeIsRememberedForAWhile(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	g := NewGrants()
	g.now = func() time.Time { return at }
	g.Granted("user-1", "node-a", at)
	g.Revoked("user-1", "node-a", at.Add(time.Hour))

	if !g.Held("user-1", "node-a", at.Add(2*time.Hour)) {
		t.Fatal("догоняющую расписку отбили")
	}
	if g.Held("user-1", "node-a", at.Add(30*24*time.Hour)) {
		t.Fatal("месячной давности расписку приняли")
	}
}

// Возврат на ту же ноду снимает отметку о снятии, иначе она протухнет посреди
// живой работы
func TestReGrantClearsTheEnd(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	g := NewGrants()
	g.now = func() time.Time { return at }
	g.Granted("user-1", "node-a", at)
	g.Revoked("user-1", "node-a", at.Add(time.Hour))
	g.Granted("user-1", "node-a", at.Add(2*time.Hour))

	if !g.Held("user-1", "node-a", at.Add(20*24*time.Hour)) {
		t.Fatal("вернувшуюся ноду забыли")
	}
}
