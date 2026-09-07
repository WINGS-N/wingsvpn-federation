package domainrules

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/features"
)

type dailySource struct {
	loads []features.HourlyLoad
	err   error
}

func (s dailySource) HourlyLoad(time.Time) ([]features.HourlyLoad, error) {
	return s.loads, s.err
}

// Круг разбора обязан выписать обвинение ровной полке и не тронуть ни спящего,
// ни сову: провал ищется в тихих часах по сортировке, а не в ночных
func TestDailyLoopAccusesOnlyTheShelf(t *testing.T) {
	flat := features.HourlyLoad{SubjectID: "farm", Days: 7}
	sleeper := features.HourlyLoad{SubjectID: "sleeper", Days: 7}
	owl := features.HourlyLoad{SubjectID: "owl", Days: 7}
	for hour := 0; hour < 24; hour++ {
		flat.Hits[hour] = 4000
		// Обычный человек спит ночью
		if hour >= 2 && hour <= 7 {
			sleeper.Hits[hour] = 40
		} else {
			sleeper.Hits[hour] = 3000
		}
		// Сова спит днём, и провал у неё ровно такой же, просто в других часах
		if hour >= 10 && hour <= 15 {
			owl.Hits[hour] = 40
		} else {
			owl.Hits[hour] = 3000
		}
	}

	var accused []string
	loop := NewDailyLoop(dailySource{loads: []features.HourlyLoad{flat, sleeper, owl}},
		func(signal *fedpb.AbuseSignal, _ string) {
			if signal.GetKind() == fedpb.AbuseKind_ABUSE_KIND_FLAT_RHYTHM {
				accused = append(accused, signal.GetProfileId())
			}
		}, nil)
	loop.Once()

	if len(accused) != 1 || accused[0] != "farm" {
		t.Fatalf("обвинили не тех: %v", accused)
	}
}

// Хранилище отвалилось - разбор молчит, а не сыплет обвинениями в пустоту
func TestDailyLoopStaysQuietWhenTheStoreIsDown(t *testing.T) {
	var accused int
	loop := NewDailyLoop(dailySource{err: errBoom}, func(*fedpb.AbuseSignal, string) { accused++ }, nil)
	loop.Once()
	if accused != 0 {
		t.Fatalf("на мёртвом хранилище выписали %d обвинений", accused)
	}
}

type boom struct{}

func (boom) Error() string { return "хранилище отвалилось" }

var errBoom = boom{}
