package features

import (
	"sort"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Суточный разбор идёт ОТДЕЛЬНО от десятиминутного, потому что в окне на десять
// минут суток не видно вообще. И судит он не по пустому часу: туннель в РФ
// висит круглосуточно, телефон сам ходит за пушами, и полностью пустых часов не
// бывает ни у кого.
//
// Ищем ПРОВАЛ, причём в самых тихих часах по сортировке, а не в ночных нахуй:
// кто спит днём или пашет сутками, даёт такой же провал, просто в других часах.
// У человека это разы, у фермы ровная полка

// HourlyLoad - сколько обращений субъект сделал в каждый час суток и за сколько
// суток это набрано
type HourlyLoad struct {
	SubjectID string
	// Hits по часу UTC, 0-23
	Hits [24]uint64
	Days float64
}

// DailyVector - суточная форма поведения
type DailyVector struct {
	SubjectID string
	Days      float64
	Requests  uint64
	// PeakHourly и TroughHourly - медианы шести самых нагруженных и шести самых
	// тихих часов. Медиана, а не максимум с минимумом: один всплеск и один
	// провал есть у любого хуя, а рисунок суток они не описывают ни хера
	PeakHourly   float64
	TroughHourly float64
	// DropRatio - во сколько раз тихие часы тише нагруженных. У человека это
	// разы, у ровной полки около единицы, и подделать это можно только перестав
	// молотить
	DropRatio float64
	// ActiveHours - в скольких часах суток вообще что-то было
	ActiveHours int
}

// BuildDaily сводит почасовую нагрузку в суточный вектор
func BuildDaily(load HourlyLoad) DailyVector {
	v := DailyVector{SubjectID: load.SubjectID, Days: load.Days}
	hours := make([]float64, 0, 24)
	for _, hits := range load.Hits {
		v.Requests += hits
		if hits > 0 {
			v.ActiveHours++
		}
		hours = append(hours, float64(hits))
	}
	if v.Requests == 0 {
		return v
	}
	sort.Float64s(hours)
	v.TroughHourly = median(hours[:6])
	v.PeakHourly = median(hours[18:])
	if v.PeakHourly > 0 {
		v.DropRatio = v.TroughHourly / v.PeakHourly
	}
	return v
}

func median(sorted []float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

const (
	// flatDropRatio - насколько тихие часы должны догонять нагруженные, чтобы
	// говорить о полке. Порог задран нарочно: даже у того, кто вообще не
	// ложится, есть часы, когда он отошёл поссать, и картина валится в разы
	flatDropRatio = 0.6
	// flatMinHours - полка должна быть широкой. Активность в трёх часах суток
	// это не полка, а забежал и съебал
	flatMinHours = 22
	// flatMinDays - за одни сутки судить нельзя нахуй: человек мог разок
	// просидеть ночь, и ебать его за это мы не станем
	flatMinDays = 5
	// flatMinRequests - и объём должен быть настоящим. Фоновая возня телефона
	// тоже размазана ровно, но её за неделю набегает пара тысяч, то есть хуй да
	// нихуя
	flatMinRequests = 20000
)

// JudgeDaily выносит обвинение по суткам.
//
// Порог тупой и с запасом нарочно: сюда влетает только тот, у кого сутки
// напролёт ровная полка в двадцати с лишним часах, пять дней подряд и с
// настоящим объёмом. Вдобавок вес у класса мелкий - в одиночку он полосу не
// двигает, а работает только вместе с остальным. Проебёшься тут - человек
// останется без доступа ни за что
func JudgeDaily(v DailyVector) []Finding {
	if v.Days < flatMinDays || v.Requests < flatMinRequests {
		return nil
	}
	if v.ActiveHours < flatMinHours || v.DropRatio < flatDropRatio {
		return nil
	}
	return []Finding{{
		Kind: fedpb.AbuseKind_ABUSE_KIND_FLAT_RHYTHM,
		// Величина - насколько полка ровная, в сотых долях
		Count: uint32(v.DropRatio * 100),
		Why:   "активность ровной полкой круглые сутки, провала нет ни в один час",
	}}
}

// DailyWindow - за какой срок смотрится ритм. Неделя переживает и командировку,
// и загул, а короче пяти суток судить нельзя вообще нахуй
const DailyWindow = 7 * 24 * time.Hour

// Values отдаёт суточные признаки числами для обучения
func (v DailyVector) Values() map[string]float64 {
	return map[string]float64{
		"daily_days":         v.Days,
		"daily_requests":     float64(v.Requests),
		"daily_peak_hourly":  v.PeakHourly,
		"daily_trough":       v.TroughHourly,
		"daily_drop_ratio":   v.DropRatio,
		"daily_active_hours": float64(v.ActiveHours),
	}
}
