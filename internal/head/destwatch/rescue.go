package destwatch

import (
	"context"
	"time"
)

// RescueEvery - как часто смотрим, кому из нод поплохело
const RescueEvery = 5 * time.Minute

// failuresBeforeSwap - сколько кругов подряд зонд должен обосраться, прежде чем
// мы полезем менять ноде dest. Один провал это сеть моргнула, а вот три подряд
// это уже диагноз
const failuresBeforeSwap = 3

// swapCooldown - сколько не трогаем ноду после смены. Смена dest перезапускает
// Xray и рвёт живые соединения, дёргать её каждые пять минут это издевательство
// и над донором, и над юзерами
const swapCooldown = 30 * time.Minute

// NodeHealth - что зонды намеряли по ноде
type NodeHealth struct {
	NodeID string
	// OK - хоть один транспорт протащил байты за окно
	OK bool
	// Dest - чем нода прикидывается сейчас
	Dest string
}

// Fleet - откуда берём состояние и куда пишем новый dest
type Fleet interface {
	// ProbeHealth отдаёт свежие замеры по каждой ноде
	ProbeHealth(within time.Duration) []NodeHealth
	// PickDest выбирает ноде другую цель, не ту, что сейчас
	PickDest(nodeID, avoid string) (string, bool)
	// SetDest прибивает ноде новый dest и толкает ей конфиг
	SetDest(nodeID, dest string) error
}

// Rescuer вытаскивает ноды, которые из страны не работают.
//
// Смотреть на dest со стороны башки бесполезно: она сидит не там, где юзеры, и
// у неё всё отвечает прекрасно. Разваливается связка dest и подписи, которую
// видно только оттуда, откуда реально ходят. Поэтому решает зонд
type Rescuer struct {
	fleet Fleet
	log   func(string, ...any)
	now   func() time.Time
	// misses - сколько кругов подряд нода мимо
	misses map[string]int
	// swapped - когда ей последний раз меняли dest
	swapped map[string]time.Time
	// window - за какой срок считаем замеры свежими
	window time.Duration
}

func NewRescuer(fleet Fleet, log func(string, ...any)) *Rescuer {
	return &Rescuer{
		fleet: fleet, log: log, now: time.Now,
		misses: map[string]int{}, swapped: map[string]time.Time{},
		window: 20 * time.Minute,
	}
}

// Run спасает по расписанию
func (r *Rescuer) Run(ctx context.Context) {
	ticker := time.NewTicker(RescueEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Once()
		}
	}
}

// Once - один круг
func (r *Rescuer) Once() {
	now := r.now()
	for _, health := range r.fleet.ProbeHealth(r.window) {
		if health.OK {
			// Ожила - забываем ей грехи, иначе следующий одиночный провал
			// сложится со старыми и дёрнет смену на ровном месте
			delete(r.misses, health.NodeID)
			continue
		}
		r.misses[health.NodeID]++
		if r.misses[health.NodeID] < failuresBeforeSwap {
			continue
		}
		if last, ok := r.swapped[health.NodeID]; ok && now.Sub(last) < swapCooldown {
			continue
		}
		next, ok := r.fleet.PickDest(health.NodeID, health.Dest)
		if !ok {
			if r.log != nil {
				r.log("destwatch: node %s is dark and there is nothing to swap its dest to", health.NodeID)
			}
			continue
		}
		if err := r.fleet.SetDest(health.NodeID, next); err != nil {
			if r.log != nil {
				r.log("destwatch: node %s dest not swapped: %v", health.NodeID, err)
			}
			continue
		}
		r.swapped[health.NodeID] = now
		r.misses[health.NodeID] = 0
		if r.log != nil {
			r.log("destwatch: node %s is dark from the probes, dest %s -> %s",
				health.NodeID, health.Dest, next)
		}
	}
}
