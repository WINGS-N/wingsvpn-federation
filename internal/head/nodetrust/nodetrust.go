// Package nodetrust держит доверие к НОДАМ, а не к людям.
//
// Нода тоже может пиздеть: завысить трафик ради выплаты, молча не отдавать
// профили, светить зелёным здоровьем, пока через неё не течёт нихуя.
//
// Из ВЫДАЧИ это доверие ноду не убирает и убирать не должно. Достижимость
// решают зонды, а тут считается репутация для линейки выплат: платить по
// самоотчёту нельзя, а вот резать выплату тому, чьи цифры не сходятся с
// подписями клиентов, как раз и есть смысл всей затеи
package nodetrust

import (
	"sort"
	"sync"
	"time"
)

// Reason - за что ноде поплохело
type Reason string

const (
	// ReasonOverclaim - нода насчитала заметно больше, чем клиенты подписали
	ReasonOverclaim Reason = "overclaim"
	// ReasonProbeFail - зонд из страны не может через неё протащить байты
	ReasonProbeFail Reason = "probe_fail"
	// ReasonFlapping - нода то есть, то нет
	ReasonFlapping Reason = "flapping"
	// ReasonProfileDrop - конфиг применён, а профили не обслуживаются
	ReasonProfileDrop Reason = "profile_drop"
	// ReasonSelfDealing - весь трафик ноды висит на паре клиентов, то есть она
	// с большой вероятностью обслуживает своего же хозяина
	ReasonSelfDealing Reason = "self_dealing"
	// ReasonBlindWatch - трафик через ноду идёт, а наблюдений она не шлёт нихуя
	ReasonBlindWatch Reason = "blind_watch"
	// ReasonUnmanagedRelay - релей не заперт на своём WireGuard и может увести
	// трафик куда угодно мимо нас
	ReasonUnmanagedRelay Reason = "unmanaged_relay"
)

// weights - во что обходится каждая претензия
var weights = map[Reason]float64{
	// Дороже всех: расхождение объёма это либо кривой учёт, либо попытка
	// получить деньги за трафик, которого не было
	ReasonOverclaim:   30,
	ReasonProbeFail:   18,
	ReasonFlapping:    10,
	ReasonProfileDrop: 22,
	// Наравне с провалом зондов: сам по себе перекос не доказывает подлога,
	// доказывает его совпадение с другими сигналами
	ReasonSelfDealing: 18,
	// Ослепшая нода стоит дорого: без доменов и отпечатков Oracle слеп нахуй,
	// и ферма на такой ноде живёт вечно
	ReasonBlindWatch: 25,
	// Дороже всего вместе с overclaim: релей с чужим бэкендом уводит
	// расшифрованный трафик туда, где мы не видим и не режем нихуя
	ReasonUnmanagedRelay: 30,
}

// halfLife - за сколько претензия теряет половину веса. Неделя: нода могла
// починиться, и таскать за ней старый грех вечно незачем
const halfLife = 7 * 24 * time.Hour

// StartingTrust - с чего начинает новая нода. Сверху, потому что она пока
// ничего плохого не сделала
const StartingTrust = 100

// Пороги для ВЫПЛАТ, не для выдачи. Тёмную ноду из ротации убирают зонды, а
// здесь решается, сколько ей причитается за отданный трафик
const (
	// ReducedBelow - ниже этого выплата режется: цифрам верим наполовину
	ReducedBelow = 60
	// UnpaidBelow - ниже этого не платим вовсе, пока не выправится
	UnpaidBelow = 30
)

// Claim - одна претензия к ноде
type Claim struct {
	NodeID string
	Reason Reason
	// Magnitude - насколько всё плохо, в своих единицах для каждой причины.
	// Насыщается, а не умножается в лоб: один провал не должен топить ноду
	Magnitude float64
	At        time.Time
}

// Verdict - что мы думаем о ноде
type Verdict struct {
	NodeID string
	Trust  int
	// Reasons - вклад каждой претензии, чтобы донору было что показать, когда
	// он спросит, почему за месяц начислили меньше
	Reasons map[Reason]float64
	At      time.Time
}

// Reduced - выплата этой ноде режется
func (v Verdict) Reduced() bool { return v.Trust < ReducedBelow }

// Unpaid - выплата не начисляется вовсе
func (v Verdict) Unpaid() bool { return v.Trust < UnpaidBelow }

// PayoutFactor - какая доля начисления доходит до донора.
//
// Не ноль и не единица рывком: репутация вещь плавная, и обрубать выплату по
// одному подозрению значит наказывать за сбойный день
func (v Verdict) PayoutFactor() float64 {
	switch {
	case v.Trust >= ReducedBelow:
		return 1
	case v.Trust >= UnpaidBelow:
		// Между порогами платим пропорционально доверию, а не половину наугад
		return float64(v.Trust-UnpaidBelow) / float64(ReducedBelow-UnpaidBelow)
	default:
		return 0
	}
}

// Judge копит претензии и считает доверие
type Judge struct {
	mu     sync.Mutex
	claims map[string][]Claim
	now    func() time.Time
	retain time.Duration
}

func NewJudge() *Judge {
	return &Judge{claims: map[string][]Claim{}, now: time.Now, retain: 30 * 24 * time.Hour}
}

// Observe принимает претензию
func (j *Judge) Observe(c Claim) {
	if c.NodeID == "" || c.Reason == "" {
		return
	}
	if c.At.IsZero() {
		c.At = j.now()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	kept := j.claims[c.NodeID][:0]
	cutoff := j.now().Add(-j.retain)
	for _, old := range j.claims[c.NodeID] {
		if old.At.After(cutoff) {
			kept = append(kept, old)
		}
	}
	j.claims[c.NodeID] = append(kept, c)
}

// Judge считает текущее доверие
func (j *Judge) Judge(nodeID string) Verdict {
	j.mu.Lock()
	claims := append([]Claim(nil), j.claims[nodeID]...)
	j.mu.Unlock()

	now := j.now()
	reasons := map[Reason]float64{}
	penalty := 0.0
	for _, c := range claims {
		weight, ok := weights[c.Reason]
		if !ok {
			continue
		}
		decay := 1.0
		for age := now.Sub(c.At); age >= halfLife; age -= halfLife {
			decay /= 2
		}
		cost := weight * magnitude(c.Magnitude) * decay
		reasons[c.Reason] += cost
		penalty += cost
	}
	trust := StartingTrust - int(penalty)
	if trust < 0 {
		trust = 0
	}
	return Verdict{NodeID: nodeID, Trust: trust, Reasons: reasons, At: now}
}

// Accused перечисляет ноды, к которым есть претензии, от худшей к лучшей
func (j *Judge) Accused() []Verdict {
	j.mu.Lock()
	ids := make([]string, 0, len(j.claims))
	for id := range j.claims {
		ids = append(ids, id)
	}
	j.mu.Unlock()

	out := make([]Verdict, 0, len(ids))
	for _, id := range ids {
		out = append(out, j.Judge(id))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Trust < out[b].Trust })
	return out
}

// magnitude насыщает величину. Один провал зонда это не приговор, а вот
// двадцать подряд уже разговор
func magnitude(value float64) float64 {
	switch {
	case value <= 1:
		return 1
	case value <= 3:
		return 1.3
	case value <= 8:
		return 1.6
	case value <= 20:
		return 2
	default:
		return 2.5
	}
}
