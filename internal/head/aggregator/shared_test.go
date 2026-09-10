package aggregator

import (
	"testing"
	"time"
)

type memShared struct {
	published []NodeShare
	stored    []NodeShare
}

func (m *memShared) PublishNodes(rows []NodeShare) error {
	m.published = rows
	return nil
}

func (m *memShared) LoadNodes() ([]NodeShare, error) { return m.stored, nil }

// Ноды соседней реплики обязаны попадать в общий вид: иначе лендинг показывает
// то весь флот, то его половину, смотря кому достался запрос
func TestЧужиеНодыВходятВОбщийСрез(t *testing.T) {
	now := time.Now()
	a := New()
	a.Ingest(Sample{NodeID: "node-mine", DonorID: "admin-1", BootID: "boot", At: now})
	a.Ingest(Sample{
		NodeID: "node-mine", DonorID: "admin-1", BootID: "boot",
		UpBytes: 100, DownBytes: 200, At: now.Add(time.Second),
	})

	store := &memShared{stored: []NodeShare{
		{NodeID: "node-theirs", DonorID: "admin-2", Up: 1000, Down: 2000, Sessions: 3, At: now},
		{NodeID: "node-mine", DonorID: "admin-1", Up: 999999, Down: 999999, At: now},
	}}
	done := make(chan struct{})
	go a.SyncShared(done, store, 5*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if snap := a.Global(); snap.NodesTotal == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(done)

	snap := a.Global()
	if snap.NodesTotal != 2 {
		t.Fatalf("во флоте %d нод, а должно быть 2", snap.NodesTotal)
	}
	if snap.UpBytes < 1000 {
		t.Fatalf("трафик чужой ноды потерялся: up=%d", snap.UpBytes)
	}
	// Свою ноду знаем точнее из памяти, и чужая запись не должна её раздувать
	if snap.UpBytes >= 999999 {
		t.Fatalf("чужая запись затёрла нашу ноду: up=%d", snap.UpBytes)
	}
}
