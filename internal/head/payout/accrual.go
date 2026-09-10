package payout

import (
	"math/big"
	"sort"
	"time"
)

// Начисление за период считается тут, и только за ОТДАННЫЙ ТРАФИК. Фикса за
// аптайм нет нарочно: нода может месяц светить зелёным здоровьем и не отдать ни
// байта, и платить ей за факт существования значит кормить пустые VPS.
//
// Зонды при этом никуда не делись, но работают гейтом, а не слагаемым: не
// подтвердили достижимость из страны - не начисляем вообще нихуя, сколько бы
// нода себе ни насчитала

// bytesPerGiB - в гигабайтах считается ставка, в байтах приходят счётчики
const bytesPerGiB = 1 << 30

// factorScale - множитель доверия хранится целым в сотых долях процента.
// Float тут нельзя: деньги обязаны считаться одинаково на любой машине
const factorScale = 10_000

// NodeVolume - всё, что известно про одну ноду за период
type NodeVolume struct {
	NodeID  string
	DonorID string
	// Address - куда донору платить. Пустой означает, что донор ещё не сказал
	// свой кошелёк, и начисление ему копится, но в эпоху не попадёт
	Address string
	// SelfBytes - сколько нода насчитала себе сама, ReceiptBytes - сколько
	// подписали клиенты. Платим по меньшему: это два числа с противоположным
	// интересом, и завысить их одновременно нельзя, не сговорившись
	SelfBytes    uint64
	ReceiptBytes uint64
	// ProbeConfirmed - протащил ли зонд через неё байты из страны. Без этого
	// нода в глазах юзера мертва, и платить за неё не за что
	ProbeConfirmed bool
	ProbeChecksOK  uint32
	ProbeChecks    uint32
	VerifiedHours  float64
	// FactorBps - множитель от репутации, 10000 это полная выплата. Приходит из
	// nodetrust: цифры не сошлись с расписками - режем деньги, а не выдачу
	FactorBps uint32
}

// Rate - сколько микро-USDT стоит гигабайт отданного трафика
type Rate struct {
	MicroPerGiB Micro
}

// Billable - за сколько байт этой ноде вообще причитается
func (n NodeVolume) Billable() uint64 {
	if !n.ProbeConfirmed {
		return 0
	}
	if n.ReceiptBytes < n.SelfBytes {
		return n.ReceiptBytes
	}
	return n.SelfBytes
}

// amountFor считает деньги целочисленно и через big, потому что байты умножить
// на ставку это легко за пределы uint64, а молча переполниться на деньгах -
// худшее, что тут может случиться
func amountFor(billable uint64, rate Rate, factorBps uint32) Micro {
	if billable == 0 || rate.MicroPerGiB == 0 || factorBps == 0 {
		return 0
	}
	if factorBps > factorScale {
		factorBps = factorScale
	}
	amount := new(big.Int).SetUint64(billable)
	amount.Mul(amount, new(big.Int).SetUint64(uint64(rate.MicroPerGiB)))
	amount.Mul(amount, new(big.Int).SetUint64(uint64(factorBps)))
	// Делим в конце, чтобы округление съедало копейки один раз, а не на каждом
	// шаге. Вниз - в нашу пользу, донору не начисляется то, чего он не отдал
	amount.Div(amount, new(big.Int).SetUint64(uint64(bytesPerGiB)*factorScale))
	if !amount.IsUint64() {
		// Столько денег быть не может, и молча отдать мусор нельзя
		return 0
	}
	return Micro(amount.Uint64())
}

// AmountFor - сколько причитается за одну ноду. Отдельно от свода по донорам,
// потому что донору показывают разбивку по машинам, и считать её вторым кодом
// значит однажды показать не то, что начислено
func AmountFor(node NodeVolume, rate Rate) Micro {
	return amountFor(node.Billable(), rate, node.FactorBps)
}

// AccrueNodes сводит ноды в начисления по донорам.
//
// Донор с тремя нодами получает ОДНО начисление: платим человеку, а не железу,
// и в эпохе у него один лист
func AccrueNodes(nodes []NodeVolume, rate Rate, start, end time.Time) []Accrual {
	byDonor := map[string]*Accrual{}
	for _, node := range nodes {
		amount := amountFor(node.Billable(), rate, node.FactorBps)
		entry, ok := byDonor[node.DonorID]
		if !ok {
			entry = &Accrual{DonorID: node.DonorID, PeriodStart: start, PeriodEnd: end}
			byDonor[node.DonorID] = entry
		}
		entry.Amount += amount
		// Основание копится и по непролезшим нодам: донор спросит, почему за
		// эту ноду ноль, и ответ должен быть в цифрах, а не на словах
		entry.Basis.ReceiptBytes += node.ReceiptBytes
		entry.Basis.ProbeChecksOK += node.ProbeChecksOK
		entry.Basis.ProbeChecksTotal += node.ProbeChecks
		entry.Basis.VerifiedHours += node.VerifiedHours
	}
	out := make([]Accrual, 0, len(byDonor))
	for _, entry := range byDonor {
		out = append(out, *entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DonorID < out[j].DonorID })
	return out
}

// EpochLeaves превращает начисления в листья.
//
// Донор без кошелька пропускается: в лист его положить не с чем, а выдумывать
// адрес за него нельзя. Начисление у него в леджере остаётся и попадёт в
// следующую эпоху, когда он кошелёк наконец укажет
func EpochLeaves(accruals []Accrual, address func(donorID string) (string, bool)) []Leaf {
	out := make([]Leaf, 0, len(accruals))
	for _, a := range accruals {
		if a.Amount == 0 {
			continue
		}
		addr, ok := address(a.DonorID)
		if !ok || addr == "" {
			continue
		}
		out = append(out, Leaf{Address: addr, Amount: a.Amount})
	}
	return out
}
