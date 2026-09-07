package aggregator

import "time"

// NodeShare - что одна реплика знает про свою ноду.
//
// Сессии агентов висят каждая на своём поде, поэтому в памяти у реплики только
// её ноды. Без общего места вторая реплика отдаёт куцую картину, и цифры на
// лендинге скачут в зависимости от того, кому досталcя запрос
type NodeShare struct {
	NodeID   string
	DonorID  string
	Up       uint64
	Down     uint64
	Probe    uint64
	Sessions uint32
	Streams  uint32
	UpRate   float64
	DownRate float64
	At       time.Time
}

// SharedStore - общее место, через которое реплики видят ноды друг друга
type SharedStore interface {
	PublishNodes(rows []NodeShare) error
	LoadNodes() ([]NodeShare, error)
}

// mine собирает ноды этой реплики для публикации
func (a *Aggregator) mine() []NodeShare {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]NodeShare, 0, len(a.nodes))
	for id, n := range a.nodes {
		out = append(out, NodeShare{
			NodeID: id, DonorID: n.donorID,
			Up: n.totalUp, Down: n.totalDown, Probe: n.totalProbe,
			Sessions: n.sessions, Streams: n.streams,
			UpRate: n.upRate, DownRate: n.downRate,
			At: n.lastAt,
		})
	}
	return out
}

// SyncShared держит общее место в согласии с памятью, пока живёт done.
//
// Публикуем своих и забираем чужих одним тиком: реже - и лендинг отстаёт, чаще
// - и запись раз в секунду упирается в базу без всякой пользы
func (a *Aggregator) SyncShared(done <-chan struct{}, store SharedStore, every time.Duration) {
	a.syncSharedWith(done, store, nil, every)
}

// SyncSharedAndLifetime вдобавок подтягивает счётчик за всё время из общего
// места: он живёт в памяти каждой реплики, и без этого лендинг показывает
// разные итоги в зависимости от того, кому достался запрос
func (a *Aggregator) SyncSharedAndLifetime(
	done <-chan struct{},
	store SharedStore,
	lifetime LifetimeStore,
	every time.Duration,
) {
	a.syncSharedWith(done, store, lifetime, every)
}

func (a *Aggregator) syncSharedWith(
	done <-chan struct{},
	store SharedStore,
	lifetime LifetimeStore,
	every time.Duration,
) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			_ = store.PublishNodes(a.mine())
			return
		case <-ticker.C:
			if err := store.PublishNodes(a.mine()); err != nil {
				continue
			}
			rows, err := store.LoadNodes()
			if err != nil {
				continue
			}
			a.mu.Lock()
			shared := make(map[string]NodeShare, len(rows))
			for _, row := range rows {
				shared[row.NodeID] = row
			}
			a.shared = shared
			a.mu.Unlock()
			if lifetime == nil {
				continue
			}
			// Только вверх: реплика, поднятая с пустой памятью, иначе откатила
			// бы итог, который посетители уже видели
			if stored, err := lifetime.Load(); err == nil {
				a.LoadLifetime(stored)
			}
		}
	}
}
