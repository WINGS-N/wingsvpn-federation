package boost

import (
	"errors"
	"math/rand"
	"testing"
)

var names = []string{"domains_per_hour", "bytes_per_request", "long_lived_share"}

// makeSet лепит выборку с понятным правилом внутри: нарушитель это дохуя имён
// при крошечном обмене. Модель обязана допереть до этого сама
func makeSet(n int, seed int64) []Sample {
	rng := rand.New(rand.NewSource(seed))
	out := make([]Sample, 0, n)
	for i := 0; i < n; i++ {
		abusive := i%2 == 0
		var domains, bytesPer, longLived float64
		if abusive {
			domains = 150 + rng.Float64()*300
			bytesPer = 100 + rng.Float64()*600
			longLived = 0
		} else {
			domains = rng.Float64() * 60
			bytesPer = 4000 + rng.Float64()*80000
			longLived = rng.Float64() * 0.4
		}
		label := 0.0
		if abusive {
			label = 1
		}
		out = append(out, Sample{
			Values: map[string]float64{
				"domains_per_hour":  domains,
				"bytes_per_request": bytesPer,
				"long_lived_share":  longLived,
			},
			Label: label,
		})
	}
	return out
}

func TestItRefusesToLearnFromNothing(t *testing.T) {
	_, err := Train(names, makeSet(10, 1), DefaultParams())
	var notEnough ErrNotEnough
	if !errors.As(err, &notEnough) {
		t.Fatalf("на десяти строках оно согласилось учиться: %v", err)
	}
}

func TestItActuallyLearnsTheRule(t *testing.T) {
	model, err := Train(names, makeSet(600, 7), DefaultParams())
	if err != nil {
		t.Fatalf("обучение разъебалось: %v", err)
	}

	// Проверяем на свежих данных, а не на тех же, иначе меряем зубрёжку, а не
	// понимание, и радуемся хуйне
	right := 0
	holdout := makeSet(200, 99)
	for _, s := range holdout {
		score := model.Score(s.Values)
		if (score >= 0.5) == (s.Label == 1) {
			right++
		}
	}
	if got := float64(right) / float64(len(holdout)); got < 0.9 {
		t.Fatalf("на новых данных модель угадывает только %.2f", got)
	}
}

func TestABusyProfileScoresHigherThanAQuietOne(t *testing.T) {
	model, err := Train(names, makeSet(600, 3), DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	abusive := model.Score(map[string]float64{
		"domains_per_hour": 400, "bytes_per_request": 200, "long_lived_share": 0,
	})
	quiet := model.Score(map[string]float64{
		"domains_per_hour": 12, "bytes_per_request": 50000, "long_lived_share": 0.3,
	})
	if abusive <= quiet {
		t.Fatalf("перебор оценён не выше спокойного профиля: %.3f против %.3f", abusive, quiet)
	}
}

func TestModelSurvivesTheWire(t *testing.T) {
	model, err := Train(names, makeSet(400, 11), DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := model.Encode()
	if err != nil {
		t.Fatalf("упаковка разъебалась: %v", err)
	}
	back, err := Decode(blob)
	if err != nil {
		t.Fatalf("распаковка разъебалась: %v", err)
	}
	sample := map[string]float64{
		"domains_per_hour": 300, "bytes_per_request": 300, "long_lived_share": 0,
	}
	if before, after := model.Score(sample), back.Score(sample); before != after {
		t.Fatalf("после сериализации вердикт поехал: %.6f против %.6f", before, after)
	}
	if back.Version() != Version || back.TrainedOn() != 400 {
		t.Fatalf("метаданные потеряли: %q %d", back.Version(), back.TrainedOn())
	}
}

// Порядок признаков живёт в самой модели, поэтому перестановка колонок местами
// не должна ничего наебашивать
func TestFeatureOrderIsPinnedToTheModel(t *testing.T) {
	model, err := Train(names, makeSet(400, 5), DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{
		"long_lived_share": 0, "bytes_per_request": 200, "domains_per_hour": 400,
	}
	if got := model.Score(values); got < 0.5 {
		t.Fatalf("карта признаков читается не по именам: %.3f", got)
	}
	if len(model.Importance()) == 0 {
		t.Fatal("модель не говорит, по чему она судит")
	}
}
