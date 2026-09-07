package features

import "testing"

// Человек спит, и это видно: ночью единицы обращений против сотен днём. Такого
// обвинять нельзя ни при каком объёме
func TestDailyLeavesASleepingHumanAlone(t *testing.T) {
	load := HourlyLoad{SubjectID: "u1", Days: 7}
	for hour := 0; hour < 24; hour++ {
		if hour >= 1 && hour <= 7 {
			load.Hits[hour] = 200
			continue
		}
		load.Hits[hour] = 9000
	}
	v := BuildDaily(load)
	if v.DropRatio > 0.1 {
		t.Fatalf("ночной провал не посчитан: drop=%.3f", v.DropRatio)
	}
	if got := JudgeDaily(v); len(got) != 0 {
		t.Fatalf("спящего человека обвинили: %+v", got)
	}
}

// Ровная полка круглые сутки несколько дней подряд - это работа, а не жизнь
func TestDailyCatchesAFlatShelf(t *testing.T) {
	load := HourlyLoad{SubjectID: "farm", Days: 7}
	for hour := 0; hour < 24; hour++ {
		load.Hits[hour] = 5000
	}
	v := BuildDaily(load)
	if v.DropRatio < 0.9 {
		t.Fatalf("полка не распознана как ровная: drop=%.3f", v.DropRatio)
	}
	got := JudgeDaily(v)
	if len(got) != 1 {
		t.Fatalf("ровную полку не заметили: %+v", got)
	}
}

// Одни сутки ничего не доказывают: человек мог разок просидеть ночь
func TestDailyNeedsSeveralDays(t *testing.T) {
	load := HourlyLoad{SubjectID: "night-owl", Days: 1}
	for hour := 0; hour < 24; hour++ {
		load.Hits[hour] = 5000
	}
	if got := JudgeDaily(BuildDaily(load)); len(got) != 0 {
		t.Fatalf("обвинили по одним суткам: %+v", got)
	}
}

// Фоновая возня телефона тоже размазана по суткам ровно, но объёма в ней нет
func TestDailyIgnoresBackgroundNoise(t *testing.T) {
	load := HourlyLoad{SubjectID: "phone", Days: 7}
	for hour := 0; hour < 24; hour++ {
		load.Hits[hour] = 12
	}
	if got := JudgeDaily(BuildDaily(load)); len(got) != 0 {
		t.Fatalf("обвинили фоновую возню: %+v", got)
	}
}

// Активность в трёх часах суток - это заход, а не полка
func TestDailyIgnoresANarrowWindow(t *testing.T) {
	load := HourlyLoad{SubjectID: "burst", Days: 5}
	for hour := 10; hour < 13; hour++ {
		load.Hits[hour] = 4000
	}
	if got := JudgeDaily(BuildDaily(load)); len(got) != 0 {
		t.Fatalf("обвинили короткий заход: %+v", got)
	}
}
