package domainrules

import (
	"context"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/features"
)

// DailyEvery - как часто крутится суточный разбор. Раз в шесть часов: рисунок
// суток за час нихуя не меняется, а гонять недельную выборку чаще - это просто
// жечь базу впустую
const DailyEvery = 6 * time.Hour

// DailySource отдаёт почасовую нагрузку за срок
type DailySource interface {
	HourlyLoad(since time.Time) ([]features.HourlyLoad, error)
}

// DailyLoop судит по суточному ритму. Отдельно от десятиминутного разбора,
// потому что в коротком окне суток не видно ни хрена
type DailyLoop struct {
	source DailySource
	accuse Accuser
	log    func(string, ...any)
	now    func() time.Time
}

func NewDailyLoop(source DailySource, accuse Accuser, log func(string, ...any)) *DailyLoop {
	return &DailyLoop{source: source, accuse: accuse, log: log, now: time.Now}
}

// SetNow подменяет часы. Нужно только тестам
func (l *DailyLoop) SetNow(now func() time.Time) { l.now = now }

// Run крутит разбор, пока жив ctx. Первый круг сразу: после выката башки данные
// за неделю уже лежат, и ждать шесть часов хуй знает зачем
func (l *DailyLoop) Run(ctx context.Context) {
	l.Once()
	ticker := time.NewTicker(DailyEvery)
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

// Once - один круг суточного разбора
func (l *DailyLoop) Once() {
	since := l.now().UTC().Add(-features.DailyWindow)
	loads, err := l.source.HourlyLoad(since)
	if err != nil {
		if l.log != nil {
			l.log("domainrules: hourly load unreadable: %v", err)
		}
		return
	}
	for _, load := range loads {
		vector := features.BuildDaily(load)
		for _, f := range features.JudgeDaily(vector) {
			l.accuse(&fedpb.AbuseSignal{
				ProfileId:     load.SubjectID,
				Kind:          f.Kind,
				Count:         f.Count,
				WindowSeconds: uint32(features.DailyWindow.Seconds()),
			}, "")
			if l.log != nil {
				l.log("domainrules: %s accused of %s (%s)", load.SubjectID, f.Kind, f.Why)
			}
		}
	}
}
