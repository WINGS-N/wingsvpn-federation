package oracle

import "time"

// Донат греет доверие, но индульгенцию нихуя не покупает.
//
// Логика простая: кто занёс в общий котёл, ведёт себя не как ферма - фермы
// приходят брать, а не давать. Поэтому донат гасит часть штрафов, и мелкие
// грехи задонатившего не роняют его в урезанную полосу.
//
// Потолок при этом обязателен: без него любой скамер просто оплачивает себе
// право работать, и весь Oracle превращается в ёбаный прайс-лист

// creditPerUSDT - сколько очков доверия греет один USDT
const creditPerUSDT = 2.0

// maxCredit - выше этого донат не греет, сколько бы ни занесли. Тридцать очков
// это ровно ширина урезанной полосы: из карантина донатом хуй выкупишься
const maxCredit = 30.0

// creditHalfLife - за сколько тает половина. Месяц: за прошлогодний донат
// спасибо, но доверие держится на поведении, а не на старой квитанции
const creditHalfLife = 30 * 24 * time.Hour

// Credit - один занос в общий котёл
type Credit struct {
	SubjectID string
	// AmountMicro - миллионные доли USDT, как и везде в деньгах
	AmountMicro uint64
	At          time.Time
}

// creditValue считает, сколько очков даёт занос на текущий момент
func creditValue(credits []Credit, now time.Time) float64 {
	var total float64
	for _, c := range credits {
		age := now.Sub(c.At)
		if age < 0 {
			age = 0
		}
		decay := 1.0
		for remaining := age; remaining >= creditHalfLife; remaining -= creditHalfLife {
			decay /= 2
		}
		total += float64(c.AmountMicro) / 1_000_000 * creditPerUSDT * decay
	}
	if total > maxCredit {
		return maxCredit
	}
	return total
}

// Donate записывает занос
func (j *Judge) Donate(c Credit) {
	if c.SubjectID == "" || c.AmountMicro == 0 {
		return
	}
	if c.At.IsZero() {
		c.At = j.now()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.credits == nil {
		j.credits = map[string][]Credit{}
	}
	j.credits[c.SubjectID] = append(j.credits[c.SubjectID], c)
}

// Credit отдаёт текущий кредит доверия субъекта
func (j *Judge) Credit(subjectID string) float64 {
	j.mu.Lock()
	credits := append([]Credit(nil), j.credits[subjectID]...)
	j.mu.Unlock()
	return creditValue(credits, j.now())
}

// LoadCredits поднимает заносы из хранилища при старте: иначе выкат башки
// стирает всё, за что люди уже заплатили, и получается свинство
func (j *Judge) LoadCredits(credits []Credit) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.credits == nil {
		j.credits = map[string][]Credit{}
	}
	for _, c := range credits {
		j.credits[c.SubjectID] = append(j.credits[c.SubjectID], c)
	}
}
