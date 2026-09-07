package destwatch

import (
	"testing"
	"time"
)

type fakeFleet struct {
	health []NodeHealth
	pool   []string
	swaps  map[string]string
}

func newFleet(health ...NodeHealth) *fakeFleet {
	return &fakeFleet{
		health: health,
		pool:   []string{"good-one.example:443", "good-two.example:443"},
		swaps:  map[string]string{},
	}
}

func (f *fakeFleet) ProbeHealth(time.Duration) []NodeHealth { return f.health }

func (f *fakeFleet) PickDest(_, avoid string) (string, bool) {
	for _, candidate := range f.pool {
		if candidate != avoid {
			return candidate, true
		}
	}
	return "", false
}

func (f *fakeFleet) SetDest(nodeID, dest string) error {
	f.swaps[nodeID] = dest
	return nil
}

func rescuerAt(fleet Fleet, now time.Time) *Rescuer {
	r := NewRescuer(fleet, nil)
	r.now = func() time.Time { return now }
	return r
}

// Одиночный провал это сеть моргнула. Дёргать за него dest значит рвать живые
// соединения у всех, кто на этой ноде сидит
func TestOneMissDoesNotSwapAnything(t *testing.T) {
	fleet := newFleet(NodeHealth{NodeID: "node-1", OK: false, Dest: "dead.example:443"})
	r := rescuerAt(fleet, time.Unix(1_700_000_000, 0))
	r.Once()
	if len(fleet.swaps) != 0 {
		t.Fatalf("сменили dest с одного провала: %+v", fleet.swaps)
	}
}

func TestPersistentDarknessSwapsTheDest(t *testing.T) {
	fleet := newFleet(NodeHealth{NodeID: "node-1", OK: false, Dest: "good-one.example:443"})
	r := rescuerAt(fleet, time.Unix(1_700_000_000, 0))
	for i := 0; i < failuresBeforeSwap; i++ {
		r.Once()
	}
	if fleet.swaps["node-1"] != "good-two.example:443" {
		t.Fatalf("нода третий круг тёмная, а dest не тронули: %+v", fleet.swaps)
	}
}

// Ожила - грехи забываем, иначе следующий одиночный провал сложится со старыми
func TestRecoveryClearsTheCount(t *testing.T) {
	fleet := newFleet(NodeHealth{NodeID: "node-1", OK: false, Dest: "good-one.example:443"})
	r := rescuerAt(fleet, time.Unix(1_700_000_000, 0))
	r.Once()
	r.Once()

	fleet.health = []NodeHealth{{NodeID: "node-1", OK: true, Dest: "good-one.example:443"}}
	r.Once()

	fleet.health = []NodeHealth{{NodeID: "node-1", OK: false, Dest: "good-one.example:443"}}
	r.Once()
	if len(fleet.swaps) != 0 {
		t.Fatalf("после выздоровления старые провалы всё равно дёрнули смену: %+v", fleet.swaps)
	}
}

// Смена dest рвёт живые соединения, поэтому дёргать ноду каждые пять минут
// нельзя, даже если она всё ещё тёмная
func TestCooldownStopsThrashing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fleet := newFleet(NodeHealth{NodeID: "node-1", OK: false, Dest: "good-one.example:443"})
	r := rescuerAt(fleet, now)
	for i := 0; i < failuresBeforeSwap; i++ {
		r.Once()
	}
	first := fleet.swaps["node-1"]
	fleet.swaps = map[string]string{}
	// Нода теперь прикидывается новым dest, как и в жизни после смены
	fleet.health = []NodeHealth{{NodeID: "node-1", OK: false, Dest: first}}
	fleet.pool = append(fleet.pool, "good-three.example:443")

	// Ещё три круга сразу же, кулдаун ещё не вышел
	for i := 0; i < failuresBeforeSwap; i++ {
		r.Once()
	}
	if len(fleet.swaps) != 0 {
		t.Fatalf("сменили dest второй раз внутри кулдауна: %+v", fleet.swaps)
	}

	r.now = func() time.Time { return now.Add(swapCooldown + time.Minute) }
	for i := 0; i < failuresBeforeSwap; i++ {
		r.Once()
	}
	if fleet.swaps["node-1"] == "" || fleet.swaps["node-1"] == first {
		t.Fatalf("после кулдауна dest не сменили: %+v", fleet.swaps)
	}
}

func TestNothingToSwapToIsNotACrash(t *testing.T) {
	fleet := newFleet(NodeHealth{NodeID: "node-1", OK: false, Dest: "only.example:443"})
	fleet.pool = []string{"only.example:443"}
	r := rescuerAt(fleet, time.Unix(1_700_000_000, 0))
	for i := 0; i < failuresBeforeSwap+2; i++ {
		r.Once()
	}
	if len(fleet.swaps) != 0 {
		t.Fatalf("подсунули ноде тот же самый dest: %+v", fleet.swaps)
	}
}
