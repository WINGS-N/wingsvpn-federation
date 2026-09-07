package payout

import "math/big"

// Ставка не высасывается из пальца и не обещается наперёд из воздуха: сколько
// в казне лежит, столько и раздаём. Пустая казна означает пустую эпоху, а не
// долг, который потом нечем закрыть

// RateBounds - рамки, за которые ставка не выходит
type RateBounds struct {
	// Cap - потолок. Выше него не платим даже при набитой казне: раздать всё за
	// одну эпоху значит остаться без денег на следующую
	Cap Micro
	// Floor - пол. Ниже него платить бессмысленно: начисляется пыль, а комиссии
	// за её раздачу больше самой пыли
	Floor Micro
	// SharePct - какую долю казны готовы потратить за эпоху. Остальное резерв:
	// донаты приходят рывками, и подчистую выгребать нельзя нахуй
	SharePct uint32
}

// AnnounceRate считает ставку на СЛЕДУЮЩУЮ эпоху.
//
// Объявляется заранее и внутри эпохи не двигается: донор должен знать цену до
// того, как повёз трафик, а не после. Пересчитать задним числом - это поменять
// правила после игры
func AnnounceRate(bounds RateBounds, treasuryMicro uint64, forecastGiB uint64) Micro {
	if bounds.Cap == 0 || forecastGiB == 0 || treasuryMicro == 0 {
		return 0
	}
	share := bounds.SharePct
	if share == 0 || share > 100 {
		share = 100
	}
	// Считаем в big: казна в микродолях умножается на долю, и на больших числах
	// uint64 переполняется молча
	budget := new(big.Int).SetUint64(treasuryMicro)
	budget.Mul(budget, big.NewInt(int64(share)))
	budget.Div(budget, big.NewInt(100))
	budget.Div(budget, new(big.Int).SetUint64(forecastGiB))

	rate := Micro(0)
	if budget.IsUint64() {
		rate = Micro(budget.Uint64())
	} else {
		rate = bounds.Cap
	}
	if rate > bounds.Cap {
		rate = bounds.Cap
	}
	// Ниже пола не платим вовсе: пыль раздавать дороже, чем не раздавать
	if rate < bounds.Floor {
		return 0
	}
	return rate
}

// ForecastGiB прикидывает трафик следующей эпохи по прошлым.
//
// Экспоненциальное сглаживание, а не голое среднее: одна разовая пиковая неделя
// иначе задирает прогноз и роняет ставку на ровном месте
func ForecastGiB(history []uint64) uint64 {
	if len(history) == 0 {
		return 0
	}
	// Вес свежего замера. Треть: реагируем на рост, но не пляшем от каждого
	// всплеска
	const freshWeight = 3
	smoothed := history[0]
	for _, value := range history[1:] {
		smoothed = (value + smoothed*(freshWeight-1)) / freshWeight
	}
	return smoothed
}
