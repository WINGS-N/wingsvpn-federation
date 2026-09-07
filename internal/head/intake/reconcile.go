package intake

import (
	"context"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// ReconcileEvery - как часто сверяем цифры ноды с подписями клиентов
const ReconcileEvery = 30 * time.Minute

// silenceGrace - сколько ждём расписок, прежде чем считать молчание ответом.
// Телефон бывает офлайн, у него бывает дохлая сеть, и рубить за это сразу
// значит выебать человека за плохой вайфай
const silenceGrace = 2 * time.Hour

// minTrafficToExpect - с какого объёма расписки уже обязаны быть. Мелочь
// проскакивает ниже порога самого клиента, и требовать за неё подпись глупо
const minTrafficToExpect = 32 << 20

// Ledger - что нода насчитала за участника
type Ledger interface {
	// Usage - сколько флот записал на этого участника
	Usage(subjectID string) uint64
	// Users - все, у кого есть доступ
	Users() []string
}

// Signed - что участник подтвердил своей подписью
type Signed interface {
	// HasKey - зарегистрировал ли человек ключ. Без ключа расписку подписать
	// физически нечем, и обвинять за её отсутствие - значит наказывать за то,
	// что у нас самих не доехало
	HasKey(subjectID string) (bool, error)
	SignedBytes(subjectID string, since time.Time) (uint64, error)
	LastReceiptAt(subjectID string) (time.Time, error)
}

// Reconciler сверяет одно с другим и обвиняет молчунов
type Reconciler struct {
	ledger Ledger
	signed Signed
	accuse func(*fedpb.AbuseSignal, string)
	now    func() time.Time
	log    func(string, ...any)
	// seen помнит, сколько нода насчитала на прошлом круге: обвинять надо за
	// свежий трафик без расписок, а не за старый долг по кругу
	seen map[string]uint64
}

func NewReconciler(ledger Ledger, signed Signed, accuse func(*fedpb.AbuseSignal, string), log func(string, ...any)) *Reconciler {
	return &Reconciler{
		ledger: ledger, signed: signed, accuse: accuse,
		now: time.Now, log: log, seen: map[string]uint64{},
	}
}

// Run сверяет по расписанию
func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(ReconcileEvery)
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

// Once - один круг сверки
func (r *Reconciler) Once() {
	now := r.now()
	for _, subject := range r.ledger.Users() {
		used := r.ledger.Usage(subject)
		previous, known := r.seen[subject]
		r.seen[subject] = used
		// Первый круг после старта башки ничего не знает о прошлом, и вся
		// накопленная сумма выглядела бы как свежий трафик без расписок. Так
		// можно разом обвинить весь флот на ровном месте
		if !known {
			continue
		}
		// Счётчик поехал назад, значит период закрыли. Дельта тут ничего не
		// значит, ждём следующего круга
		if used < previous {
			continue
		}
		fresh := used - previous
		if fresh < minTrafficToExpect {
			continue
		}

		// Ключа нет - подписывать нечем. Это либо старое приложение, либо наш
		// собственный проёб в доставке, и в обоих случаях виноват не человек
		if hasKey, err := r.signed.HasKey(subject); err == nil && !hasKey {
			continue
		}

		last, err := r.signed.LastReceiptAt(subject)
		if err != nil {
			if r.log != nil {
				r.log("intake: receipts unreadable for %s: %v", subject, err)
			}
			continue
		}
		if !last.IsZero() && now.Sub(last) < silenceGrace {
			continue
		}
		r.accuse(&fedpb.AbuseSignal{
			ProfileId:     subject,
			Kind:          fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS,
			Count:         uint32(fresh >> 20),
			WindowSeconds: uint32(ReconcileEvery.Seconds()),
		}, "")
		if r.log != nil {
			r.log("intake: %s moved %d MB with no signed receipts", subject, fresh>>20)
		}
	}
}
