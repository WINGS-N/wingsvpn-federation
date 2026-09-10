// Package epochs закрывает расчётный период и сводит его в один корень.
//
// Собирает разрозненное в кучу: что нода насчитала себе, что подписали клиенты,
// пустила ли она байты из страны и во что её ставит репутация. Отдельным
// пакетом, потому что источников много и тащить эту сборку в payout значит
// пришить расчёт денег к реестру и агрегатору намертво
package epochs

import (
	"errors"
	"time"

	"wingsnet.org/federation/internal/head/payout"
)

// NodeInfo - нода глазами расчёта
type NodeInfo struct {
	NodeID  string
	DonorID string
	// ProbeConfirmed - протащил ли зонд через неё байты за период. Нода,
	// которую из страны не видно, для юзера мертва, и платить не за что
	ProbeConfirmed bool
	ProbeChecks    uint32
	ProbeChecksOK  uint32
	VerifiedHours  float64
}

// Nodes отдаёт флот на момент закрытия периода
type Nodes interface {
	ForPayout(since time.Time) []NodeInfo
	// NodeByAddress нужен потому, что клиент подписывает адрес, а не наш
	// внутренний id: без перевода расписки не сойдутся ни с одной нодой
	NodeByAddress(address string) (string, bool)
}

// Claimed - накопленные счётчики нод. Итог за всё время, а не окно, поэтому
// период считается приростом
type Claimed interface {
	NodeTraffic(since time.Time) (map[string]uint64, error)
}

// Confirmed - что подписали клиенты за закрытое окно
type Confirmed interface {
	SignedByNodeBetween(start, end time.Time) (map[string]uint64, error)
}

// Trust отдаёт множитель выплаты по репутации ноды
type Trust interface {
	FactorBps(nodeID string) uint32
}

// Addresses говорит, куда донору платить
type Addresses interface {
	Address(donorID string) (string, bool)
}

// Staked отвечает, внёс ли донор залог. Без залога он работает бесплатно: врать
// на самоотчёте выгодно ровно до тех пор, пока за вранье нечего отнять
type Staked interface {
	Staked(donorID string) bool
}

// Store хранит эпохи и базу счётчиков, от которой считается прирост
type Store interface {
	// Next - номер, под которым уедет следующая эпоха. Первая идёт нулевой:
	// программа в цепочке заводится с next_epoch = 0 и принимает только его,
	// так что нумерация с единицы означала бы отказ на каждой публикации
	Next() (uint64, error)
	Save(epoch *payout.Epoch, donorByAddress map[string]string) error
	Baselines() (map[string]uint64, error)
	SaveBaselines(map[string]uint64) error
}

// ErrNothingToPay - за период никому ничего не причитается
var ErrNothingToPay = errors.New("epochs: nothing to pay for this period")

// Collector закрывает периоды
type Collector struct {
	nodes     Nodes
	claimed   Claimed
	confirmed Confirmed
	trust     Trust
	addresses Addresses
	staked    Staked
	store     Store
	rate      payout.Rate
	// history - объёмы прошлых эпох в гигабайтах, по ним считается прогноз
	history []uint64
	log     func(string, ...any)
}

func NewCollector(nodes Nodes, claimed Claimed, confirmed Confirmed, trust Trust,
	addresses Addresses, store Store, rate payout.Rate, log func(string, ...any)) *Collector {
	return &Collector{
		nodes: nodes, claimed: claimed, confirmed: confirmed,
		trust: trust, addresses: addresses, store: store, rate: rate, log: log,
	}
}

// SetStaked включает проверку залога. Не задана - платим как раньше, всем с
// кошельком: тумблер выплат и без того выключен по умолчанию
func (c *Collector) SetStaked(staked Staked) { c.staked = staked }

// payable отвечает, куда платить донору, и отсекает тех, кто залог не внёс
func (c *Collector) payable(donorID string) (string, bool) {
	address, ok := c.addresses.Address(donorID)
	if !ok {
		return "", false
	}
	if c.staked != nil && !c.staked.Staked(donorID) {
		if c.log != nil {
			c.log("epochs: donor %s has no stake, this period is donated", donorID)
		}
		return "", false
	}
	return address, true
}

// Close считает период и кладёт эпоху.
//
// Расписки приходят по адресам, счётчики по нодам, а платим донорам - поэтому
// половина работы тут это перевод одного в другое
func (c *Collector) Close(start, end time.Time) (*payout.Epoch, error) {
	claimed, err := c.claimed.NodeTraffic(start)
	if err != nil {
		return nil, err
	}
	baselines, err := c.store.Baselines()
	if err != nil {
		return nil, err
	}
	signed, err := c.confirmed.SignedByNodeBetween(start, end)
	if err != nil {
		return nil, err
	}

	// Расписка называет ноду адресом, потому что больше клиент про неё нихуя не
	// знает. Несколько адресов одной ноды складываются в неё же
	byNode := map[string]uint64{}
	for address, bytes := range signed {
		nodeID, ok := c.nodes.NodeByAddress(address)
		if !ok {
			// Нода могла уйти из флота, а расписки за неё остаться. Платить
			// некому, но и молчать об этом не надо
			if c.log != nil {
				c.log("epochs: %d bytes signed for address %s that no node claims", bytes, address)
			}
			continue
		}
		byNode[nodeID] += bytes
	}

	fleet := c.nodes.ForPayout(start)
	volumes := make([]payout.NodeVolume, 0, len(fleet))
	nextBaselines := make(map[string]uint64, len(fleet))
	for _, node := range fleet {
		total := claimed[node.NodeID]
		nextBaselines[node.NodeID] = total
		volumes = append(volumes, payout.NodeVolume{
			NodeID:         node.NodeID,
			DonorID:        node.DonorID,
			SelfBytes:      grown(baselines[node.NodeID], total),
			ReceiptBytes:   byNode[node.NodeID],
			ProbeConfirmed: node.ProbeConfirmed,
			ProbeChecks:    node.ProbeChecks,
			ProbeChecksOK:  node.ProbeChecksOK,
			VerifiedHours:  node.VerifiedHours,
			FactorBps:      c.trust.FactorBps(node.NodeID),
		})
	}

	number, err := c.store.Next()
	if err != nil {
		return nil, err
	}

	accruals := payout.AccrueNodes(volumes, c.rate, start, end)
	c.rememberVolume(volumes)
	donorByAddress := map[string]string{}
	leaves := payout.EpochLeaves(accruals, func(donorID string) (string, bool) {
		address, ok := c.payable(donorID)
		if ok {
			donorByAddress[address] = donorID
		}
		return address, ok
	})
	if len(leaves) == 0 {
		// База всё равно двигается: иначе неоплаченный период приплюсуется к
		// следующему и донор получит за него дважды
		if err := c.store.SaveBaselines(nextBaselines); err != nil {
			return nil, err
		}
		return nil, ErrNothingToPay
	}

	epoch, err := payout.BuildEpoch(number, start, end, leaves)
	if err != nil {
		return nil, err
	}
	if err := c.store.Save(epoch, donorByAddress); err != nil {
		return nil, err
	}
	if err := c.store.SaveBaselines(nextBaselines); err != nil {
		return nil, err
	}
	if c.log != nil {
		c.log("epochs: closed %d with %d leaves totalling %s USDT",
			epoch.Number, len(epoch.Leaves), epoch.Total.FormatUSDT())
	}
	return epoch, nil
}

// grown - прирост счётчика за период.
//
// Счётчик ноды может уехать вниз: её забыли и завели заново, или переставили с
// нуля. Тогда весь текущий итог и есть прирост, а вычитать старую базу значит
// подарить донору отрицательный период
func grown(base, current uint64) uint64 {
	if current < base {
		return current
	}
	return current - base
}

// Pending - что набежало в текущем незакрытом периоде.
//
// Донору мало итоговой цифры: он вправе видеть, какая машина сколько принесла и
// почему одна принесла ноль. Считается тем же кодом, что и закрытие периода,
// иначе показанное и начисленное разъедутся
func (c *Collector) Pending(donorID string, start time.Time) ([]payout.NodeVolume, payout.Micro, error) {
	claimed, err := c.claimed.NodeTraffic(start)
	if err != nil {
		return nil, 0, err
	}
	baselines, err := c.store.Baselines()
	if err != nil {
		return nil, 0, err
	}
	signed, err := c.confirmed.SignedByNodeBetween(start, time.Now().UTC())
	if err != nil {
		return nil, 0, err
	}
	byNode := map[string]uint64{}
	for address, bytes := range signed {
		if nodeID, ok := c.nodes.NodeByAddress(address); ok {
			byNode[nodeID] += bytes
		}
	}

	var volumes []payout.NodeVolume
	var total payout.Micro
	for _, node := range c.nodes.ForPayout(start) {
		if donorID != "" && node.DonorID != donorID {
			continue
		}
		volume := payout.NodeVolume{
			NodeID:         node.NodeID,
			DonorID:        node.DonorID,
			SelfBytes:      grown(baselines[node.NodeID], claimed[node.NodeID]),
			ReceiptBytes:   byNode[node.NodeID],
			ProbeConfirmed: node.ProbeConfirmed,
			ProbeChecks:    node.ProbeChecks,
			ProbeChecksOK:  node.ProbeChecksOK,
			FactorBps:      c.trust.FactorBps(node.NodeID),
		}
		volumes = append(volumes, volume)
		total += payout.AmountFor(volume, c.rate)
	}
	return volumes, total, nil
}

// Rate отдаёт действующий прайс
func (c *Collector) Rate() payout.Rate { return c.rate }

// rememberVolume копит, сколько эпоха реально унесла: по этому ряду и считается
// прогноз на следующую
func (c *Collector) rememberVolume(volumes []payout.NodeVolume) {
	var billable uint64
	for _, volume := range volumes {
		billable += volume.Billable()
	}
	const keep = 8
	c.history = append(c.history, billable/(1<<30))
	if len(c.history) > keep {
		c.history = c.history[len(c.history)-keep:]
	}
}

// HistoryGiB - сколько гигабайт уносили прошлые эпохи
func (c *Collector) HistoryGiB() []uint64 { return c.history }

// SetRate ставит цену на текущий период.
//
// Ставка плавает по казне и объявляется на период вперёд: сколько денег лежит,
// столько и раздаём. Пустая казна означает пустую эпоху, а не долг, который
// потом нечем закрыть нахуй
func (c *Collector) SetRate(rate payout.Rate) { c.rate = rate }
