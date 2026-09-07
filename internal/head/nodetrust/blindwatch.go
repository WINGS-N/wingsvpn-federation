package nodetrust

import (
	"sync"
	"time"
)

// Нода обязана стучать, куда ходят её клиенты: без доменов и отпечатков Oracle
// слеп, и ферма на такой ноде живёт вечно. Молчание при живом трафике значит
// либо старого агента, либо донора, который наблюдение осознанно выключил, и оба
// случая одинаково нам не годятся

// blindWindow - сколько нода может молчать при живом трафике, прежде чем это
// станет претензией. Батчи ходят раз в полминуты, час это уже не сбой сети
const blindWindow = time.Hour

// blindMinBytes - ниже этого молчание законно: без трафика и наблюдать нечего
const blindMinBytes = 1 << 30

// WatchAudit следит, кто перестал стучать
type WatchAudit struct {
	judge *Judge

	mu sync.Mutex
	// bytes - сколько нода протащила с последнего наблюдения
	bytes map[string]uint64
	// lastSeen - когда от ноды последний раз приезжали домены
	lastSeen map[string]time.Time
	// accused - когда её за это уже наказывали, чтобы не долбить каждую минуту
	accused map[string]time.Time
	// rebase - ноды, чью базу надо взять заново: они только что отчитались
	rebase map[string]bool
	now    func() time.Time
	log    func(string, ...any)
}

// SetLogger включает журнал: без него нода теряет доверие молча, и никто не
// поймёт, за что порезали выплату
func (w *WatchAudit) SetLogger(fn func(string, ...any)) { w.log = fn }

func NewWatchAudit(judge *Judge) *WatchAudit {
	return &WatchAudit{
		judge:    judge,
		bytes:    map[string]uint64{},
		lastSeen: map[string]time.Time{},
		accused:  map[string]time.Time{},
		rebase:   map[string]bool{},
		now:      time.Now,
	}
}

// ObserveDomains отмечает, что нода стучит
func (w *WatchAudit) ObserveDomains(nodeID string) {
	if nodeID == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastSeen[nodeID] = w.now()
	// Итога ноды тут нет, поэтому базу переставит ближайший Sweep
	w.rebase[nodeID] = true
}

// Sweep берёт итоги нод и наказывает тех, кто возит трафик молча.
//
// Прирост считаем сами по накопленным итогам, а не подписываемся на поток
// дельт: пропущенный тик тогда ничего не портит, а нода не может отмолчаться,
// проскочив между замерами
func (w *WatchAudit) Sweep(totals map[string]uint64) {
	now := w.now()
	w.mu.Lock()
	var blind []string
	for nodeID, total := range totals {
		if w.rebase[nodeID] {
			delete(w.rebase, nodeID)
			w.bytes[nodeID] = total
			continue
		}
		seen, ok := w.lastSeen[nodeID]
		if !ok {
			// Ноду видим впервые: отсчёт молчания идёт отсюда, иначе только что
			// зачисленной сразу прилетает обвинение
			w.lastSeen[nodeID] = now
			w.bytes[nodeID] = total
			continue
		}
		if total < w.bytes[nodeID] {
			// Счётчики уехали назад, значит нода перезапустилась: базу берём
			// заново, иначе разница уйдёт в минус и молчание проскочит
			w.bytes[nodeID] = total
			continue
		}
		if total-w.bytes[nodeID] < blindMinBytes || now.Sub(seen) < blindWindow {
			continue
		}
		if last, ok := w.accused[nodeID]; ok && now.Sub(last) < blindWindow {
			continue
		}
		w.accused[nodeID] = now
		blind = append(blind, nodeID)
	}
	w.mu.Unlock()

	for _, nodeID := range blind {
		w.judge.Observe(Claim{NodeID: nodeID, Reason: ReasonBlindWatch, Magnitude: 1, At: now})
		if w.log != nil {
			w.log("nodetrust: node %s carries traffic and reports no observations", nodeID)
		}
	}
}

// ObserveRelayMode наказывает ноду, чей релей не заперт на своём WireGuard.
//
// Спрашиваем это у самого процесса по его управляющему gRPC, а не смотрим на
// флаги: флаги в чужом systemd правит кто угодно
func (w *WatchAudit) ObserveRelayMode(nodeID string, federation bool) {
	if nodeID == "" || federation {
		return
	}
	now := w.now()
	w.mu.Lock()
	last, ok := w.accused[nodeID+"|relay"]
	if ok && now.Sub(last) < blindWindow {
		w.mu.Unlock()
		return
	}
	w.accused[nodeID+"|relay"] = now
	w.mu.Unlock()
	w.judge.Observe(Claim{NodeID: nodeID, Reason: ReasonUnmanagedRelay, Magnitude: 1, At: now})
	if w.log != nil {
		w.log("nodetrust: relay on node %s is not locked to its own wireguard", nodeID)
	}
}

// WatchSweepEvery - как часто проверять, кто ослеп. Чаще незачем: окно молчания
// час, и любой более частый проход просто крутит те же цифры
const WatchSweepEvery = 10 * time.Minute
