package aggregator

import "time"

// NodeTraffic - сколько каждая нода насчитала себе за всё время.
//
// Отдаёт накопленный итог, а не окно: сверка с расписками сравнивает приросты,
// и хранить тут ещё и историю окон незачем. Аргумент since взят ради контракта
// аудитора, сам итог от него не зависит
func (a *Aggregator) NodeTraffic(_ time.Time) (map[string]uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]uint64, len(a.nodes))
	for id, node := range a.nodes {
		// Трафик зондов не в счёт: его нагнали мы сами, и предъявлять ноде
		// расписки за собственные замеры было бы свинством
		total := node.totalUp + node.totalDown
		if total > node.totalProbe {
			total -= node.totalProbe
		} else {
			total = 0
		}
		out[id] = total
	}
	for id, n := range a.shared {
		if _, ours := a.nodes[id]; ours {
			continue
		}
		total := n.Up + n.Down
		if total > n.Probe {
			total -= n.Probe
		} else {
			total = 0
		}
		out[id] = total
	}
	return out, nil
}
