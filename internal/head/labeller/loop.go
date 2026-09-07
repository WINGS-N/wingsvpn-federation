package labeller

import (
	"context"
	"time"
)

// Every - как часто размечаем накопленное. Раз в час: снимки капают каждые
// десять минут, и копить их сутками смысла нет, а долбить API чаще - платить за
// приветствие
const Every = time.Hour

// batchesPerRound - сколько пачек уходит за один круг.
//
// Одной пачкой в час очередь в десятки тысяч снимков разгребалась бы месяц.
// Пачки идут подряд ещё и потому, что промпт кешируется: со второй вход
// дешевеет вчетверо, то есть гнать их подряд ВЫГОДНЕЕ, чем размазывать по часам
const batchesPerRound = 10

// By - чем помечаем машинную разметку. Метку человека она перебивать не должна
// ни при каких раскладах
const By = "claude"

// Loop размечает снимки пачками
type Loop struct {
	client  *Client
	store   Store
	version string
	log     func(string, ...any)
	// domains - куда ходил обвинённый. Второй заход показывает их модели: по
	// голым числам она не отличит человека в ютубе от чекера
	domains      Domains
	domainWindow time.Duration
}

func NewLoop(client *Client, store Store, version string, log func(string, ...any)) *Loop {
	return &Loop{client: client, store: store, version: version, log: log}
}

// Run размечает по расписанию
func (l *Loop) Run(ctx context.Context) {
	l.Once(ctx)
	ticker := time.NewTicker(Every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.Once(ctx)
		}
	}
}

// Once прогоняет несколько пачек подряд. Всю очередь за раз не выжираем: у API
// свои лимиты, а разметка это фон, а не пожар
func (l *Loop) Once(ctx context.Context) {
	for i := 0; i < batchesPerRound; i++ {
		if done := l.batch(ctx); done {
			return
		}
	}
}

// batch размечает одну пачку. Возвращает true, когда разгребать больше нечего
// или дальше идти нет смысла
func (l *Loop) batch(ctx context.Context) bool {
	snapshots, err := l.store.Unlabelled(l.version, batchSize)
	if err != nil {
		if l.log != nil {
			l.log("labeller: unlabelled rows are unreadable: %v", err)
		}
		return true
	}
	if len(snapshots) == 0 {
		return true
	}
	verdicts, err := l.client.Label(ctx, snapshots)
	if err != nil {
		if l.log != nil {
			l.log("labeller: labelling failed: %v", err)
		}
		return true
	}
	known := make(map[uint64]struct{}, len(snapshots))
	for _, s := range snapshots {
		known[s.ID] = struct{}{}
	}
	var clean []uint64
	dirty := map[uint64]string{}
	for _, v := range verdicts {
		// Модель может высрать чужой id или выдумать его - берём только то, что
		// сами и отправляли
		if _, ok := known[v.ID]; !ok {
			continue
		}
		if v.Abuse {
			dirty[v.ID] = v.Why
			continue
		}
		clean = append(clean, v.ID)
	}
	if len(clean) > 0 {
		if err := l.store.SetLabel(clean, 0, By); err != nil && l.log != nil {
			l.log("labeller: clean labels were not stored: %v", err)
		}
	}
	// Обвинение по голым числам - это ещё не приговор. Прежде чем записать
	// человека в мошенники, показываем модели, КУДА он ходил: половина
	// подозрительных цифр объясняется одним взглядом на домены
	dirty = l.reviewAccused(ctx, snapshots, dirty)
	if len(dirty) > 0 {
		if err := l.store.SetLabelWhy(dirty, 1, By); err != nil && l.log != nil {
			l.log("labeller: dirty labels were not stored: %v", err)
		}
	}
	if l.log != nil {
		l.log("labeller: labelled %d, suspicious %d", len(clean)+len(dirty), len(dirty))
	}
	// Пачка пришла неполной - значит очередь кончилась, дальше идти незачем
	return len(snapshots) < batchSize
}
