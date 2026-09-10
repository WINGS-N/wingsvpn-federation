package payout

import "testing"

// Ставку объявляем по казне: сколько лежит, столько и раздаём
func TestRateFollowsTheTreasury(t *testing.T) {
	bounds := RateBounds{Cap: 293, Floor: 10, SharePct: 60}

	// Казна на 600 USDT, прогноз 1000 GiB: 60% от 600 это 360 USDT на 1000 GiB
	rate := AnnounceRate(bounds, 600_000_000, 1000)
	if rate != bounds.Cap {
		t.Fatalf("при набитой казне ставка %d, а потолок %d", rate, bounds.Cap)
	}

	// Казна тощая: ставка обязана просесть, а не обещать невыполнимое
	rate = AnnounceRate(bounds, 100_000, 1000)
	if rate == 0 || rate >= bounds.Cap {
		t.Fatalf("на тощей казне ставка %d, а должна быть между полом и потолком", rate)
	}
}

// Пустая казна означает пустую эпоху, а не долг: лишних обещаний не даём нахуй
func TestEmptyTreasuryMeansNoRate(t *testing.T) {
	bounds := RateBounds{Cap: 293, Floor: 10, SharePct: 60}
	if rate := AnnounceRate(bounds, 0, 1000); rate != 0 {
		t.Fatalf("на пустой казне объявили %d", rate)
	}
	// Ниже пола не платим вовсе: пыль раздавать дороже, чем не раздавать
	if rate := AnnounceRate(bounds, 1000, 1_000_000); rate != 0 {
		t.Fatalf("объявили пыль: %d", rate)
	}
}

// Потолок держит: даже с казной на миллион ставка не улетает
func TestCapHolds(t *testing.T) {
	bounds := RateBounds{Cap: 293, Floor: 10, SharePct: 100}
	if rate := AnnounceRate(bounds, 1_000_000_000_000, 1); rate != 293 {
		t.Fatalf("потолок пробило: %d", rate)
	}
}

// Разовый всплеск не должен ронять ставку на следующую эпоху
func TestForecastSmoothsSpikes(t *testing.T) {
	steady := ForecastGiB([]uint64{100, 100, 100, 100})
	if steady != 100 {
		t.Fatalf("ровный ряд дал %d", steady)
	}
	spiky := ForecastGiB([]uint64{100, 100, 100, 400})
	if spiky >= 400 || spiky <= 100 {
		t.Fatalf("всплеск сгладился в %d, а должен лечь между 100 и 400", spiky)
	}
	if ForecastGiB(nil) != 0 {
		t.Fatal("без истории прогноз обязан быть нулевым")
	}
}
