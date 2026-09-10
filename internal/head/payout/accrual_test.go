package payout

import (
	"testing"
	"time"
)

const gib = uint64(1) << 30

func testRate() Rate { return Rate{MicroPerGiB: 10_000} }

// Нода, которую зонд не подтвердил, не получает нихуя - сколько бы она себе ни
// насчитала. Это и есть гейт вместо фикса за аптайм
func TestUnconfirmedNodeEarnsNothing(t *testing.T) {
	node := NodeVolume{
		NodeID: "n1", DonorID: "admin-1",
		SelfBytes: 100 * gib, ReceiptBytes: 100 * gib,
		ProbeConfirmed: false, FactorBps: factorScale,
	}
	if got := node.Billable(); got != 0 {
		t.Fatalf("к оплате %d байт, а зонды ноду не подтвердили", got)
	}
	start := time.Now()
	accruals := AccrueNodes([]NodeVolume{node}, testRate(), start, start.Add(time.Hour))
	if accruals[0].Amount != 0 {
		t.Fatalf("начислено %s неподтверждённой ноде", accruals[0].Amount.FormatUSDT())
	}
}

// Простаивающая нода тоже не получает нихуя, хотя зонды её видят прекрасно
func TestIdleConfirmedNodeEarnsNothing(t *testing.T) {
	start := time.Now()
	accruals := AccrueNodes([]NodeVolume{{
		NodeID: "n1", DonorID: "admin-1",
		ProbeConfirmed: true, ProbeChecks: 48, ProbeChecksOK: 48,
		VerifiedHours: 168, FactorBps: factorScale,
	}}, testRate(), start, start.Add(time.Hour))
	if accruals[0].Amount != 0 {
		t.Fatalf("простой оплачен на %s, а трафика не было", accruals[0].Amount.FormatUSDT())
	}
}

// Платим по меньшему из двух чисел: самоотчёт ноды и подписи клиентов
func TestPaysTheSmallerOfSelfAndReceipts(t *testing.T) {
	start := time.Now()
	liar := NodeVolume{
		NodeID: "n1", DonorID: "liar",
		SelfBytes: 100 * gib, ReceiptBytes: 10 * gib,
		ProbeConfirmed: true, FactorBps: factorScale,
	}
	honest := NodeVolume{
		NodeID: "n2", DonorID: "honest",
		SelfBytes: 10 * gib, ReceiptBytes: 12 * gib,
		ProbeConfirmed: true, FactorBps: factorScale,
	}
	got := AccrueNodes([]NodeVolume{liar, honest}, testRate(), start, start.Add(time.Hour))
	if len(got) != 2 {
		t.Fatalf("начислений %d, а доноров двое", len(got))
	}
	// 10 GiB по 10000 микро за гиг = 0.1 USDT обоим
	for _, a := range got {
		if a.Amount != Micro(100_000) {
			t.Fatalf("%s получил %s, а обоим причитается по 0.1 USDT", a.DonorID, a.Amount.FormatUSDT())
		}
	}
}

// Репутация режет деньги, а не выдачу
func TestTrustFactorCutsTheMoney(t *testing.T) {
	start := time.Now()
	node := NodeVolume{
		NodeID: "n1", DonorID: "admin-1",
		SelfBytes: 100 * gib, ReceiptBytes: 100 * gib,
		ProbeConfirmed: true, FactorBps: factorScale / 2,
	}
	got := AccrueNodes([]NodeVolume{node}, testRate(), start, start.Add(time.Hour))
	if got[0].Amount != Micro(500_000) {
		t.Fatalf("начислено %s, а с половинным доверием причитается 0.5 USDT", got[0].Amount.FormatUSDT())
	}

	node.FactorBps = 0
	got = AccrueNodes([]NodeVolume{node}, testRate(), start, start.Add(time.Hour))
	if got[0].Amount != 0 {
		t.Fatalf("нода с нулевым доверием получила %s", got[0].Amount.FormatUSDT())
	}
}

// Донору платят один раз за все его ноды, а не по разу за каждую
func TestDonorWithSeveralNodesGetsOneAccrual(t *testing.T) {
	start := time.Now()
	nodes := []NodeVolume{
		{NodeID: "n1", DonorID: "admin-1", SelfBytes: 10 * gib, ReceiptBytes: 10 * gib, ProbeConfirmed: true, FactorBps: factorScale, ProbeChecks: 10, ProbeChecksOK: 9},
		{NodeID: "n2", DonorID: "admin-1", SelfBytes: 20 * gib, ReceiptBytes: 20 * gib, ProbeConfirmed: true, FactorBps: factorScale, ProbeChecks: 10, ProbeChecksOK: 10},
	}
	got := AccrueNodes(nodes, testRate(), start, start.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("начислений %d, а донор один", len(got))
	}
	if got[0].Amount != Micro(300_000) {
		t.Fatalf("начислено %s, а за 30 GiB причитается 0.3 USDT", got[0].Amount.FormatUSDT())
	}
	if got[0].Basis.ProbeChecksTotal != 20 || got[0].Basis.ProbeChecksOK != 19 {
		t.Fatal("основание не сложилось по обеим нодам")
	}
}

// Терабайты на дорогой ставке не должны молча переполнить счётчик
func TestHugeVolumeDoesNotOverflow(t *testing.T) {
	start := time.Now()
	got := AccrueNodes([]NodeVolume{{
		NodeID: "n1", DonorID: "whale",
		SelfBytes: 900 * 1024 * gib, ReceiptBytes: 900 * 1024 * gib,
		ProbeConfirmed: true, FactorBps: factorScale,
	}}, Rate{MicroPerGiB: 1_000_000}, start, start.Add(time.Hour))
	// 900 TiB по 1 USDT за гиг это 921600 USDT
	if got[0].Amount != Micro(921_600_000_000) {
		t.Fatalf("начислено %s, а ожидалось 921600 USDT", got[0].Amount.FormatUSDT())
	}
}

// Округление всегда вниз: начислить то, чего донор не отдал, нельзя
func TestRoundingGoesDown(t *testing.T) {
	start := time.Now()
	got := AccrueNodes([]NodeVolume{{
		NodeID: "n1", DonorID: "admin-1",
		SelfBytes: 1, ReceiptBytes: 1,
		ProbeConfirmed: true, FactorBps: factorScale,
	}}, testRate(), start, start.Add(time.Hour))
	if got[0].Amount != 0 {
		t.Fatalf("за один байт начислили %s", got[0].Amount.FormatUSDT())
	}
}

// Донор без кошелька в эпоху не попадает, но и не теряется
func TestDonorWithoutWalletIsSkipped(t *testing.T) {
	accruals := []Accrual{
		{DonorID: "with-wallet", Amount: Micro(1_000_000)},
		{DonorID: "no-wallet", Amount: Micro(2_000_000)},
		{DonorID: "zero", Amount: 0},
	}
	addresses := map[string]string{"with-wallet": wallets[0], "zero": wallets[1]}
	leaves := EpochLeaves(accruals, func(id string) (string, bool) {
		addr, ok := addresses[id]
		return addr, ok
	})
	if len(leaves) != 1 {
		t.Fatalf("листьев %d, а платить есть кому одному", len(leaves))
	}
	if leaves[0].Address != wallets[0] || leaves[0].Amount != Micro(1_000_000) {
		t.Fatal("в лист попало не то начисление")
	}
}
