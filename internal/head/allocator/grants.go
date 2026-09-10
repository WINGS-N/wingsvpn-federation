package allocator

import (
	"sync"
	"time"
)

// Журнал выдачи: кому и когда башка давала ноду.
//
// Нужен, чтобы проверять расписки, не заглядывая в цифры ноды. Самоотчёт ноды
// для этого не годится в принципе: pkg/agentclient публичный, свой исполнитель
// пишется за вечер, и донор с подхуяренным агентом просто перестанет рапортовать
// трафик, отбив клиентам подписи. Журнал ведёт башка, и подделать его с ноды
// нельзя никак

// grantMemory - сколько помним выдачу после снятия. Расписка приезжает с
// опозданием до недели, и запись должна пережить ротацию
const grantMemory = 8 * 24 * time.Hour

// Grants помнит, кто на какой ноде сидел
type Grants struct {
	mu sync.Mutex
	// spans - по человеку, по ноде: когда выдали и когда сняли
	spans map[string]map[string]*grantSpan
	now   func() time.Time
}

type grantSpan struct {
	from  time.Time
	until time.Time
}

func NewGrants() *Grants {
	return &Grants{spans: map[string]map[string]*grantSpan{}, now: time.Now}
}

// Granted отмечает, что нода у человека сейчас есть
func (g *Grants) Granted(userID, nodeID string, at time.Time) {
	if userID == "" || nodeID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	byNode := g.spans[userID]
	if byNode == nil {
		byNode = map[string]*grantSpan{}
		g.spans[userID] = byNode
	}
	if span, ok := byNode[nodeID]; ok {
		// Пока нода у человека, конец не фиксируем: он ставится снятием
		span.until = time.Time{}
		return
	}
	byNode[nodeID] = &grantSpan{from: at}
}

// Revoked отмечает, что ноду сняли
func (g *Grants) Revoked(userID, nodeID string, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if span, ok := g.spans[userID][nodeID]; ok {
		span.until = at
	}
}

// Held - была ли нода у человека в это окно.
//
// Границы намеренно широкие: выдача и снятие идут не секунда в секунду с
// трафиком, а расписка закрывает пятиминутку. Задача не поймать минуту, а
// отбить подпись на ноду, которую человек не видел вовсе
func (g *Grants) Held(userID, nodeID string, windowEnd time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	span, ok := g.spans[userID][nodeID]
	if !ok {
		return false
	}
	if windowEnd.Before(span.from.Add(-time.Hour)) {
		return false
	}
	if !span.until.IsZero() && windowEnd.After(span.until.Add(grantMemory)) {
		return false
	}
	return true
}

// Forget чистит снятое и протухшее
func (g *Grants) Forget() {
	cutoff := g.now().Add(-grantMemory)
	g.mu.Lock()
	defer g.mu.Unlock()
	for userID, byNode := range g.spans {
		for nodeID, span := range byNode {
			if !span.until.IsZero() && span.until.Before(cutoff) {
				delete(byNode, nodeID)
			}
		}
		if len(byNode) == 0 {
			delete(g.spans, userID)
		}
	}
}
