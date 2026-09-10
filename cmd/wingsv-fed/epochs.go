package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"wingsnet.org/federation/internal/head/aggregator"
	"wingsnet.org/federation/internal/head/chain"
	"wingsnet.org/federation/internal/head/epochs"
	"wingsnet.org/federation/internal/head/headserver"
	"wingsnet.org/federation/internal/head/labeller"
	"wingsnet.org/federation/internal/head/nodetrust"
	"wingsnet.org/federation/internal/head/oracle"
	"wingsnet.org/federation/internal/head/payout"
	"wingsnet.org/federation/internal/head/pgstore"
	"wingsnet.org/federation/internal/head/registry"
)

// Слои сведены здесь нарочно: расчёт денег не должен знать ни про реестр, ни
// про хранилище, иначе его не проверить без половины башки

// payoutFleet показывает реестр расчёту
type payoutFleet struct {
	reg *registry.Registry
}

// ForPayout собирает флот с оценкой того, видно ли ноду из страны.
//
// Замер годится только свежий: нода, которую подтверждали неделю назад и с тех
// пор не видели, для юзера уже мертва
func (f payoutFleet) ForPayout(since time.Time) []epochs.NodeInfo {
	nodes := f.reg.List()
	out := make([]epochs.NodeInfo, 0, len(nodes))
	for _, node := range nodes {
		info := epochs.NodeInfo{NodeID: node.ID, DonorID: node.DonorID}
		for _, reach := range node.Reachability {
			if reach.At.Before(since) {
				continue
			}
			info.ProbeChecks++
			if reach.OK {
				info.ProbeChecksOK++
				info.ProbeConfirmed = true
			}
		}
		if node.LastSeen.After(since) {
			info.VerifiedHours = node.LastSeen.Sub(since).Hours()
		}
		out = append(out, info)
	}
	return out
}

func (f payoutFleet) NodeByAddress(address string) (string, bool) {
	return f.reg.NodeByAddress(address)
}

// trustFactor переводит вердикт о ноде в множитель выплаты
type trustFactor struct {
	judge *nodetrust.Judge
}

// FactorBps - доля начисления в сотых долях процента. Деньги считаются целыми,
// поэтому дробь остаётся за порогом расчёта
func (t trustFactor) FactorBps(nodeID string) uint32 {
	factor := t.judge.Judge(nodeID).PayoutFactor()
	if factor <= 0 {
		return 0
	}
	if factor >= 1 {
		return 10_000
	}
	return uint32(factor * 10_000)
}

// epochStore кладёт посчитанную эпоху в базу
type epochStore struct {
	store *pgstore.EpochStore
}

func (e epochStore) Last() (uint64, error) { return e.store.Last() }

func (e epochStore) Next() (uint64, error) { return e.store.Next() }

func (e epochStore) Unpublished(limit int) ([]uint64, error) { return e.store.Unpublished(limit) }

func (e epochStore) Unpaid(limit int) ([]uint64, error) { return e.store.Unpaid(limit) }

// Epoch собирает закрытую эпоху обратно из базы, чтобы повторить публикацию.
// Дерево пересчитывается из тех же листьев, поэтому корень выходит прежний
func (e epochStore) Epoch(number uint64) (*payout.Epoch, error) {
	row, err := e.store.Get(number)
	if err != nil {
		return nil, err
	}
	rows, err := e.store.Leaves(number)
	if err != nil {
		return nil, err
	}
	leaves := make([]payout.Leaf, 0, len(rows))
	for _, leaf := range rows {
		leaves = append(leaves, payout.Leaf{Address: leaf.Address, Amount: payout.Micro(leaf.AmountMicro)})
	}
	return payout.BuildEpoch(number, row.StartAt, row.EndAt, leaves)
}

func (e epochStore) Baselines() (map[string]uint64, error) { return e.store.Baselines() }

func (e epochStore) SaveBaselines(next map[string]uint64) error {
	return e.store.SaveBaselines(next)
}

func (e epochStore) Save(epoch *payout.Epoch, donorByAddress map[string]string) error {
	leaves := make([]pgstore.EpochLeafRow, 0, len(epoch.Leaves))
	for _, leaf := range epoch.Leaves {
		leaves = append(leaves, pgstore.EpochLeafRow{
			Number:      epoch.Number,
			Address:     leaf.Address,
			DonorID:     donorByAddress[leaf.Address],
			AmountMicro: int64(leaf.Amount),
		})
	}
	return e.store.Save(pgstore.EpochRow{
		Number:     epoch.Number,
		StartAt:    epoch.Start,
		EndAt:      epoch.End,
		Root:       epoch.Root[:],
		TotalMicro: int64(epoch.Total),
	}, leaves)
}

// payoutAddresses отдаёт расчёту кошельки доноров
type payoutAddresses struct {
	store *pgstore.EpochStore
}

func (p payoutAddresses) Address(donorID string) (string, bool) {
	address, ok, err := p.store.PayoutAddress(donorID)
	if err != nil || !ok {
		return "", false
	}
	return address, true
}

// Wallets отдаёт все кошельки разом: сторож залогов обходит доноров сам
func (p payoutAddresses) Wallets() map[string]string {
	wallets, err := p.store.PayoutWallets()
	if err != nil {
		return nil
	}
	return wallets
}

// headPayouts показывает панели то, что башка насчитала
type headPayouts struct {
	store *pgstore.EpochStore
}

func (h headPayouts) SetPayoutAddress(donorID, address string) error {
	return h.store.SetPayoutAddress(donorID, address)
}

func (h headPayouts) PayoutAddress(donorID string) (string, bool, error) {
	return h.store.PayoutAddress(donorID)
}

func (h headPayouts) StatementFor(donorID string, limit int) ([]headserver.EpochAccrual, error) {
	rows, err := h.store.StatementFor(donorID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]headserver.EpochAccrual, 0, len(rows))
	for _, row := range rows {
		out = append(out, headserver.EpochAccrual{
			Number:      row.Number,
			Start:       row.StartAt,
			End:         row.EndAt,
			AmountMicro: uint64(row.AmountMicro),
			RootHex:     hex.EncodeToString(row.Root),
			TxRef:       row.TxRef,
			PublishedAt: timeOrZero(row.PublishedAt),
		})
	}
	return out, nil
}

func (h headPayouts) RecentEpochs(limit int) ([]headserver.EpochSummary, error) {
	rows, err := h.store.Recent(limit)
	if err != nil {
		return nil, err
	}
	out := make([]headserver.EpochSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, headserver.EpochSummary{
			Number:      row.Number,
			Start:       row.StartAt,
			End:         row.EndAt,
			TotalMicro:  uint64(row.TotalMicro),
			Leaves:      uint32(row.Leaves),
			RootHex:     hex.EncodeToString(row.Root),
			TxRef:       row.TxRef,
			PublishedAt: timeOrZero(row.PublishedAt),
		})
	}
	return out, nil
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// nodeDonors говорит суду, чья это нода
type nodeDonors struct {
	reg *registry.Registry
}

func (n nodeDonors) DonorOfNode(nodeID string) (string, bool) {
	node, err := n.reg.Get(nodeID)
	if err != nil || node == nil {
		return "", false
	}
	return node.DonorID, node.DonorID != ""
}

// pendingAccruals сводит счетовода и расписание в одно окно для панели: цифры
// считает коллектор, границы периода знает цикл, а донору нужно и то и другое
type pendingAccruals struct {
	collector *epochs.Collector
	loop      *epochs.Loop
}

func (p pendingAccruals) Pending(donorID string, start time.Time) ([]payout.NodeVolume, payout.Micro, error) {
	return p.collector.Pending(donorID, start)
}

func (p pendingAccruals) Rate() payout.Rate { return p.collector.Rate() }

func (p pendingAccruals) PeriodStart() (time.Time, error) { return p.loop.PeriodStart() }

func (p pendingAccruals) Period() time.Duration { return p.loop.Period() }

// upstreamVerdicts показывает раздаче купленного, кому можно за пределы флота
type upstreamVerdicts struct {
	judge *oracle.Judge
}

func (u upstreamVerdicts) Confidence(subjectID string) (int, bool) {
	verdict := u.judge.Judge(subjectID)
	return verdict.Confidence, verdict.Band == oracle.BandFull
}

// labelStore переводит размеченные снимки из хранилища в то, что показывает
// панель. Хранилище про gRPC-слой не знает и знать не должно
type labelStore struct {
	store *pgstore.MLStore
}

func (l labelStore) Page(limit, offset int, accusedOnly bool) ([]headserver.LabelRow, int, error) {
	rows, total, err := l.store.LabelPage(limit, offset, accusedOnly)
	if err != nil {
		return nil, 0, err
	}
	out := make([]headserver.LabelRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, headserver.LabelRow{
			ID: r.ID, AtUnix: r.AtUnix, SubjectID: r.SubjectID,
			Label: r.Label, LabelBy: r.LabelBy, Why: r.Why, Values: r.Values,
		})
	}
	return out, total, nil
}

func (l labelStore) Counts() (int, int, error) { return l.store.LabelCounts() }

func (l labelStore) Judge(id uint64, label int16) error { return l.store.JudgeLabel(id, label) }

// reviewDomains показывает разбору обвинений, куда ходил человек. Хранилище про
// разметчика не знает и знать не должно
type reviewDomains struct {
	store *pgstore.DomainStore
}

func (r reviewDomains) TopDomains(subjectID string, since time.Time, limit int) ([]labeller.Domain, error) {
	rows, err := r.store.ReviewDomains(subjectID, since, limit)
	if err != nil {
		return nil, err
	}
	out := make([]labeller.Domain, 0, len(rows))
	for _, row := range rows {
		out = append(out, labeller.Domain{Name: row.Name, Hits: row.Hits, Bytes: row.Bytes})
	}
	return out, nil
}

// ProofFor собирает путь от листа донора к корню эпохи.
//
// Дерево строится заново из хранимых листьев, а не лежит готовым: пруф спрашивают
// раз в неделю на донора, а хранить дерево целиком значит держать в базе то, что
// считается за миллисекунду
func (h headPayouts) ProofFor(number uint64, address string) ([][]byte, error) {
	rows, err := h.store.Leaves(number)
	if err != nil {
		return nil, err
	}
	epoch, err := h.store.Get(number)
	if err != nil {
		return nil, err
	}
	leaves := make([]payout.Leaf, 0, len(rows))
	for _, row := range rows {
		leaves = append(leaves, payout.Leaf{Address: row.Address, Amount: payout.Micro(row.AmountMicro)})
	}
	rebuilt, err := payout.BuildEpoch(number, epoch.StartAt, epoch.EndAt, leaves)
	if err != nil {
		return nil, err
	}
	// Корень обязан сойтись с опубликованным: разъехался - значит листья в базе
	// правили после публикации, и такой пруф в цепочке не пройдёт нихуя
	if !bytes.Equal(rebuilt.Root[:], epoch.Root) {
		return nil, fmt.Errorf("epochs: root of epoch %d does not match the database", number)
	}
	proof, err := rebuilt.Proof(address)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(proof))
	for _, step := range proof {
		hop := make([]byte, 32)
		copy(hop, step[:])
		out = append(out, hop)
	}
	return out, nil
}

// epochRates связывает цикл эпох с хранилищем объявленных ставок
type epochRates struct {
	store *pgstore.EpochStore
}

func (r epochRates) AnnounceRate(periodStart time.Time, micro, treasury, forecast uint64) error {
	return r.store.AnnounceRate(pgstore.AnnouncedRateRow{
		PeriodStart:   periodStart.UTC(),
		MicroPerGiB:   int64(micro),
		TreasuryMicro: int64(treasury),
		ForecastGiB:   int64(forecast),
		AnnouncedAt:   time.Now().UTC(),
	})
}

func (r epochRates) RateFor(periodStart time.Time) (uint64, bool, error) {
	row, ok, err := r.store.RateFor(periodStart)
	if err != nil || !ok {
		return 0, false, err
	}
	return uint64(row.MicroPerGiB), true, nil
}

// chainTreasuryBalance спрашивает у цепочки, сколько денег в казне.
//
// Спрашиваем именно цепочку, а не свою базу: платить придётся из того, что там
// лежит, и разъехавшийся учёт означал бы обещания, которые нечем закрыть
type chainTreasuryBalance struct {
	client  *chain.Client
	account chain.Pubkey
}

func (t chainTreasuryBalance) Balance(ctx context.Context) (uint64, error) {
	return t.client.TokenBalance(ctx, t.account)
}

// PaidFor - что донору уже выплачено и какой транзакцией. Цифра без транзакции
// это обещание, а не выплата
func (h headPayouts) PaidFor(donorID string) (map[uint64]headserver.Payment, error) {
	rows, err := h.store.PaidFor(donorID)
	if err != nil {
		return nil, err
	}
	out := make(map[uint64]headserver.Payment, len(rows))
	for number, row := range rows {
		out[number] = headserver.Payment{Micro: row.Micro, TxRef: row.TxRef, PaidAt: row.PaidAt}
	}
	return out, nil
}

// sharedNodes - общий срез по нодам между репликами башки.
//
// Перевод лежит тут, а не в хранилище: пакет базы не должен знать про
// агрегатор, иначе импорты сходятся в кольцо
type sharedNodes struct {
	store *pgstore.NodeTrafficStore
}

func (s sharedNodes) PublishNodes(rows []aggregator.NodeShare) error {
	out := make([]pgstore.NodeTrafficRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, pgstore.NodeTrafficRow{
			NodeID: row.NodeID, DonorID: row.DonorID,
			UpBytes: int64(row.Up), DownBytes: int64(row.Down), ProbeBytes: int64(row.Probe),
			Sessions: int32(row.Sessions), Streams: int32(row.Streams),
			UpRate: row.UpRate, DownRate: row.DownRate, SeenAt: row.At,
		})
	}
	return s.store.PublishNodes(out)
}

func (s sharedNodes) LoadNodes() ([]aggregator.NodeShare, error) {
	rows, err := s.store.LoadNodes()
	if err != nil {
		return nil, err
	}
	out := make([]aggregator.NodeShare, 0, len(rows))
	for _, row := range rows {
		out = append(out, aggregator.NodeShare{
			NodeID: row.NodeID, DonorID: row.DonorID,
			Up: atLeastZero(row.UpBytes), Down: atLeastZero(row.DownBytes),
			Probe:    atLeastZero(row.ProbeBytes),
			Sessions: uint32(atLeastZero(int64(row.Sessions))),
			Streams:  uint32(atLeastZero(int64(row.Streams))),
			UpRate:   row.UpRate, DownRate: row.DownRate, At: row.SeenAt,
		})
	}
	return out, nil
}

func atLeastZero(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}
