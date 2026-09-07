package nodetrust

import (
	"context"
	"time"
)

// AuditEvery - как часто сверяем ноды с подписями клиентов
const AuditEvery = time.Hour

// auditWindow - за какой срок сравниваем. Час слишком дёрганый: клиент шлёт
// расписки окнами по пять минут и бывает офлайн, а сутки сглаживают это
const auditWindow = 24 * time.Hour

// tolerance - на сколько нода может расходиться с клиентами и это норма.
//
// Расхождение будет всегда: нода считает всё, что прошло через неё, а клиент
// только то, что дошло до него. Потери, ретрансмиты и оверхед туннеля дают
// честную разницу, и придираться к ней значит обвинить весь флот
const tolerance = 1.35

// minAuditBytes - ниже этого объёма сверять нечего, проценты на мелочи скачут
const minAuditBytes = 256 << 20

// Claimed - что нода записала себе за срок
type Claimed interface {
	// NodeTraffic - сколько нода насчитала за окно, по каждой ноде
	NodeTraffic(since time.Time) (map[string]uint64, error)
}

// Confirmed - что клиенты подписали за тот же срок
type Confirmed interface {
	// SignedByNode - сколько подписано расписками в разрезе нод. Ключ тут -
	// то, как ноду видит клиент, то есть адрес
	SignedByNode(since time.Time) (map[string]uint64, error)
}

// Resolver переводит адрес, который назвал клиент, в идентификатор ноды.
//
// Клиент внутренних id не знает и знать не должен, он подписывает то, что видит
// в ссылке. Без перевода ключи не сойдутся вообще никогда, и весь флот будет
// выглядеть как ноды без единой расписки
type Resolver interface {
	NodeByAddress(address string) (string, bool)
}

// Auditor сверяет одно с другим
type Auditor struct {
	claimed   Claimed
	confirmed Confirmed
	resolve   Resolver
	judge     *Judge
	now       func() time.Time
	log       func(string, ...any)
	// seen - что нода насчитала на прошлом круге. Сверять надо ПРИРОСТ: итог за
	// всё время против подписей за сутки разойдётся всегда, и обвинён будет
	// весь флот подряд
	seen map[string]uint64
	// lastSigned - сколько было подписано на прошлом круге, по той же причине
	lastSigned map[string]uint64
	// mix нужен, чтобы поймать ноду, обслуживающую собственного хозяина. Без
	// него сверка объёмов идёт как раньше
	mix ClientMix
	// tree и donors приходят от панели: дерево инвайтов у неё, трафик у нас
	tree   Ancestry
	donors DonorOf
}

// WatchClientMix включает разбор того, на скольких клиентах висит трафик ноды
func (a *Auditor) WatchClientMix(mix ClientMix) { a.mix = mix }

func NewAuditor(claimed Claimed, confirmed Confirmed, resolve Resolver, judge *Judge, log func(string, ...any)) *Auditor {
	return &Auditor{
		claimed: claimed, confirmed: confirmed, resolve: resolve, judge: judge,
		now: time.Now, log: log,
		seen: map[string]uint64{}, lastSigned: map[string]uint64{},
	}
}

// Run сверяет по расписанию
func (a *Auditor) Run(ctx context.Context) {
	ticker := time.NewTicker(AuditEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.Once()
			a.JudgeSelfDealing(a.mix)
		}
	}
}

// Once - один круг сверки
func (a *Auditor) Once() {
	since := a.now().Add(-auditWindow)
	claimed, err := a.claimed.NodeTraffic(since)
	if err != nil {
		if a.log != nil {
			a.log("nodetrust: node counters unreadable: %v", err)
		}
		return
	}
	signed, err := a.confirmed.SignedByNode(since)
	if err != nil {
		if a.log != nil {
			a.log("nodetrust: receipts unreadable: %v", err)
		}
		return
	}

	// Подписи сложены по адресам, а счётчики по идентификаторам. Переводим,
	// иначе не сойдётся ни один ключ
	byNode := make(map[string]uint64, len(signed))
	for address, bytes := range signed {
		id := address
		if a.resolve != nil {
			if resolved, ok := a.resolve.NodeByAddress(address); ok {
				id = resolved
			}
		}
		byNode[id] += bytes
	}

	// Ни одной подписи по всему флоту - это молчит наша сторона, а не врут все
	// ноды разом. Штрафовать тут значит наказывать доноров за нашу поломку
	anySigned := false
	for _, signed := range byNode {
		if signed > 0 {
			anySigned = true
			break
		}
	}

	for nodeID, total := range claimed {
		previous, known := a.seen[nodeID]
		a.seen[nodeID] = total
		previousSigned := a.lastSigned[nodeID]
		a.lastSigned[nodeID] = byNode[nodeID]
		// Первый круг после старта башки не знает предыстории, и весь
		// накопленный итог выглядел бы как свежее враньё
		if !known || total < previous {
			continue
		}
		claim := total - previous
		if claim < minAuditBytes {
			continue
		}
		confirmed := uint64(0)
		if byNode[nodeID] > previousSigned {
			confirmed = byNode[nodeID] - previousSigned
		}
		// Ни одной подписи при заметном трафике - это не расхождение, это
		// отсутствие второй стороны. Причина у такого разная, от старых
		// клиентов до подставных, поэтому судим мягче, чем за завышение
		if confirmed == 0 {
			if !anySigned {
				if a.log != nil {
					a.log("nodetrust: no receipts from anyone this window, skipping the audit")
				}
				continue
			}
			a.judge.Observe(Claim{
				NodeID: nodeID, Reason: ReasonOverclaim,
				Magnitude: 1, At: a.now(),
			})
			if a.log != nil {
				a.log("nodetrust: node %s claims %d MB with no signed receipts at all", nodeID, claim>>20)
			}
			continue
		}
		ratio := float64(claim) / float64(confirmed)
		if ratio <= tolerance {
			continue
		}
		// Величина это во сколько раз нода перебрала сверх допуска
		a.judge.Observe(Claim{
			NodeID: nodeID, Reason: ReasonOverclaim,
			Magnitude: ratio / tolerance, At: a.now(),
		})
		if a.log != nil {
			a.log("nodetrust: node %s claims %.2fx what clients signed (%d vs %d MB)",
				nodeID, ratio, claim>>20, confirmed>>20)
		}
	}
}
