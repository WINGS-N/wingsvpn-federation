package epochs

import (
	"context"
	"errors"
	"time"

	"wingsnet.org/federation/internal/head/payout"
)

// DefaultPeriod - за какой срок закрывается эпоха. Неделя: чаще значит гонять
// доноров клеймить по копейке и жечь их же комиссии, реже - держать людей без
// денег дольше, чем они готовы терпеть
const DefaultPeriod = 7 * 24 * time.Hour

// checkEvery - как часто смотрим, не пора ли закрывать. Тикер на неделю пережил
// бы ровно один выкат башки, поэтому проверяем часто, а закрываем по времени
const checkEvery = time.Hour

// Clock говорит, когда закончился последний закрытый период. Пустое время
// означает, что эпох ещё не было и точку отсчёта надо взять от текущего момента
type Clock interface {
	LastPeriodEnd() (time.Time, error)
	SetPeriodEnd(time.Time) error
}

// publishTimeout - сколько ждём цепочку. Публичный RPC умеет тупить, а держать
// цикл эпох на нём вечно незачем
const publishTimeout = 60 * time.Second

// Publisher уносит корень эпохи в цепочку и платит по нему донорам.
//
// Платит башка, а не донор: подпись донора программе не нужна, деньги уходят
// строго владельцу листа. Иначе человеку пришлось бы держать SOL на комиссию и
// возиться с пруфом руками, а это не выплата, а квест
type Publisher interface {
	Publish(ctx context.Context, epoch *payout.Epoch) (string, error)
	PayEveryone(ctx context.Context, epoch *payout.Epoch) (paid int, err error)
}

// Marks запоминает, что эпоха уже опубликована и какой транзакцией
type Marks interface {
	MarkPublished(number uint64, at time.Time, ref string) error
}

// Pending отдаёт эпохи, чей корень так и не уехал в цепочку.
//
// Период сдвигается сразу после закрытия, поэтому упавшая публикация без
// повтора не случится больше никогда: начисления посчитаны, а забрать их нечем
type Pending interface {
	Unpublished(limit int) ([]uint64, error)
	Epoch(number uint64) (*payout.Epoch, error)
}

// Rates хранит объявленные ставки. Объявленное не переписывается: донор повёз
// трафик под ту цену, которую видел
type Rates interface {
	AnnounceRate(periodStart time.Time, microPerGiB, treasuryMicro, forecastGiB uint64) error
	RateFor(periodStart time.Time) (microPerGiB uint64, ok bool, err error)
}

// Treasury говорит, сколько денег реально лежит в казне. Спрашиваем цепочку, а
// не свою базу: платить придётся из того, что там есть
type Treasury interface {
	Balance(ctx context.Context) (uint64, error)
}

// Loop закрывает эпохи по расписанию
type Loop struct {
	collector *Collector
	clock     Clock
	period    time.Duration
	now       func() time.Time
	log       func(string, ...any)
	publisher Publisher
	marks     Marks
	pending   Pending
	rates     Rates
	treasury  Treasury
	bounds    payout.RateBounds
}

// SetPending включает повтор публикации для эпох, которые её не пережили
func (l *Loop) SetPending(p Pending) { l.pending = p }

// SetPublisher включает публикацию в цепочку. Без него эпохи просто копятся в
// базе, и это законный режим: цепочка нужна для выплат, а не для учёта
func (l *Loop) SetPublisher(publisher Publisher, marks Marks) {
	l.publisher, l.marks = publisher, marks
}

// SetRates включает плавающую ставку. Без него цена стоит колом из конфига
func (l *Loop) SetRates(rates Rates, treasury Treasury, bounds payout.RateBounds) {
	l.rates, l.treasury, l.bounds = rates, treasury, bounds
}

func NewLoop(collector *Collector, clock Clock, period time.Duration, log func(string, ...any)) *Loop {
	if period <= 0 {
		period = DefaultPeriod
	}
	return &Loop{collector: collector, clock: clock, period: period, now: time.Now, log: log}
}

// Run крутится, пока жив ctx. Запускать только на активной реплике: две башки,
// закрывающие один период, выпишут донору две эпохи за одни и те же байты
func (l *Loop) Run(ctx context.Context) {
	// Первый заход сразу: тикер на час означал бы, что после каждого выката
	// зависшая эпоха ждёт публикации ещё час, а закрытый период - до двух
	l.Once()
	ticker := time.NewTicker(checkEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.Once()
		}
	}
}

// retryUnpublished добирает то, что не уехало с прошлых заходов
func (l *Loop) retryUnpublished() {
	if l.pending == nil || l.publisher == nil {
		return
	}
	numbers, err := l.pending.Unpublished(retryBatch)
	if err != nil {
		if l.log != nil {
			l.log("epochs: unpublished list unreadable: %v", err)
		}
		return
	}
	for _, number := range numbers {
		epoch, err := l.pending.Epoch(number)
		if err != nil {
			if l.log != nil {
				l.log("epochs: epoch %d unreadable: %v", number, err)
			}
			continue
		}
		l.publish(epoch)
	}
}

// retryBatch - сколько зависших эпох добираем за круг. Их не бывает много, а
// вешать на публичный RPC десятки транзакций подряд незачем
const retryBatch = 4

// Once закрывает период, если он уже кончился
func (l *Loop) Once() {
	l.retryUnpublished()
	last, err := l.clock.LastPeriodEnd()
	if err != nil {
		if l.log != nil {
			l.log("epochs: period mark unreadable: %v", err)
		}
		return
	}
	now := l.now().UTC()
	if last.IsZero() {
		// Первый запуск: считать назад в неизвестность нельзя, счётчики за то
		// время уже сложены в базу и период вышел бы бесконечным
		if err := l.clock.SetPeriodEnd(now); err != nil && l.log != nil {
			l.log("epochs: period mark not stored: %v", err)
		}
		return
	}
	end := last.Add(l.period)
	if end.After(now) {
		return
	}

	// Считаем по цене, объявленной на этот период. Не объявляли - работает та,
	// что стоит в конфиге: так ведёт себя башка без цепочки
	l.applyAnnounced(last)

	epoch, err := l.collector.Close(last, end)
	switch {
	case errors.Is(err, ErrNothingToPay):
		// Никому ничего не причиталось, но период всё равно закрыт: иначе он
		// приклеится к следующему и оплатится дважды
	case err != nil:
		if l.log != nil {
			l.log("epochs: closing %s..%s failed: %v", last.Format(time.RFC3339), end.Format(time.RFC3339), err)
		}
		return
	}
	if err := l.clock.SetPeriodEnd(end); err != nil && l.log != nil {
		l.log("epochs: period mark not advanced: %v", err)
	}
	l.publish(epoch)
	// Цену на следующий период объявляем сразу: донор должен видеть её до того,
	// как повезёт трафик, а не после
	l.announce(end)
}

// applyAnnounced ставит коллектору цену, объявленную на этот период
func (l *Loop) applyAnnounced(periodStart time.Time) {
	if l.rates == nil {
		return
	}
	micro, ok, err := l.rates.RateFor(periodStart)
	if err != nil {
		if l.log != nil {
			l.log("epochs: rate for %s unreadable: %v", periodStart.Format(time.RFC3339), err)
		}
		return
	}
	if !ok {
		return
	}
	l.collector.SetRate(payout.Rate{MicroPerGiB: payout.Micro(micro)})
}

// announce объявляет цену на следующий период.
//
// Считается по тому, что реально лежит в казне: пустая казна означает пустую
// эпоху, а не долг, который потом нечем закрыть нахуй
func (l *Loop) announce(periodStart time.Time) {
	if l.rates == nil || l.treasury == nil || l.bounds.Cap == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	balance, err := l.treasury.Balance(ctx)
	if err != nil {
		if l.log != nil {
			l.log("epochs: treasury unreadable, the rate stays as it was: %v", err)
		}
		return
	}
	forecast := payout.ForecastGiB(l.collector.HistoryGiB())
	rate := payout.AnnounceRate(l.bounds, balance, forecast)
	if err := l.rates.AnnounceRate(periodStart, uint64(rate), balance, forecast); err != nil && l.log != nil {
		l.log("epochs: rate for %s not stored: %v", periodStart.Format(time.RFC3339), err)
	}
	if l.log != nil {
		l.log("epochs: next period pays %d micro per GiB, treasury %d, forecast %d GiB",
			rate, balance, forecast)
	}
}

// publish уносит корень в цепочку. Без публикации эпоха остаётся бумажкой:
// начисления посчитаны, а склеймить их донор не может нихуя
func (l *Loop) publish(epoch *payout.Epoch) {
	if epoch == nil || l.publisher == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	signature, err := l.publisher.Publish(ctx, epoch)
	if err != nil {
		// Не доехало - эпоха всё равно закрыта и лежит в базе. Публикацию
		// повторит оператор, а терять посчитанное из-за тупящего RPC незачем
		if l.log != nil {
			l.log("epochs: epoch %d not published: %v", epoch.Number, err)
		}
		return
	}
	if l.marks != nil {
		if err := l.marks.MarkPublished(epoch.Number, l.now().UTC(), signature); err != nil && l.log != nil {
			l.log("epochs: publication of %d not recorded: %v", epoch.Number, err)
		}
	}

	// Платим сразу за всех. Провал одной выплаты не должен ронять остальные:
	// корень уже в цепочке, и недоплаченное добирается следующим заходом
	paid, err := l.publisher.PayEveryone(ctx, epoch)
	if l.log != nil {
		if err != nil {
			l.log("epochs: epoch %d paid %d of %d, the rest failed: %v", epoch.Number, paid, len(epoch.Leaves), err)
		} else {
			l.log("epochs: epoch %d paid out to %d donors", epoch.Number, paid)
		}
	}
}

// PeriodStart - когда начался текущий незакрытый период
func (l *Loop) PeriodStart() (time.Time, error) { return l.clock.LastPeriodEnd() }

// Period - длина расчётного периода
func (l *Loop) Period() time.Duration { return l.period }
