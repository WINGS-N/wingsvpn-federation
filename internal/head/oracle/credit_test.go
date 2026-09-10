package oracle

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

func judgeFrozenAt(now time.Time) *Judge {
	judge := NewJudge(NewRulesScorer())
	judge.now = func() time.Time { return now }
	return judge
}

// Мелкие грехи задонатившего не должны ронять его в урезанную полосу
func TestDonationLiftsASlightlyDirtySubject(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	judge := judgeFrozenAt(now)
	// Сигналов ровно столько, чтобы человек провалился под порог полной полосы
	for i := 0; i < 3; i++ {
		judge.Observe(Signal{
			ClientID: "user-1", Kind: fedpb.AbuseKind_ABUSE_KIND_PORT_SCAN,
			Count: 1, Observed: now.Add(-time.Hour),
		})
	}
	dirty := judge.Judge("user-1")
	if dirty.Band == BandFull {
		t.Fatalf("подготовка сломалась: доверие %d осталось полным", dirty.Confidence)
	}

	judge.Donate(Credit{SubjectID: "user-1", AmountMicro: 10_000_000, At: now.Add(-24 * time.Hour)})
	warm := judge.Judge("user-1")
	if warm.Confidence <= dirty.Confidence {
		t.Fatalf("донат не согрел: было %d, стало %d", dirty.Confidence, warm.Confidence)
	}
	if warm.Credit <= 0 {
		t.Fatal("кредит не попал в вердикт, и человеку нечего показать")
	}
}

// Из карантина донатом не выкупиться, сколько бы ни занесли
func TestDonationCannotBuyOutOfQuarantine(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	judge := judgeFrozenAt(now)
	for i := 0; i < 8; i++ {
		judge.Observe(Signal{
			ClientID: "scam", Kind: fedpb.AbuseKind_ABUSE_KIND_MALWARE,
			Count: 30, Observed: now.Add(-time.Hour),
		})
	}
	if judge.Judge("scam").Band != BandQuarantine {
		t.Fatal("подготовка сломалась: субъект не в карантине")
	}
	// Тысяча долларов - и всё равно карантин
	judge.Donate(Credit{SubjectID: "scam", AmountMicro: 1_000_000_000, At: now})
	if judge.Judge("scam").Band != BandQuarantine {
		t.Fatal("карантин выкуплен донатом, Oracle превратился в прайс-лист")
	}
}

// Доверие выше сотни не поднимается: чистый человек и так наверху
func TestDonationDoesNotOverfillACleanSubject(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	judge := judgeFrozenAt(now)
	judge.Donate(Credit{SubjectID: "clean", AmountMicro: 50_000_000, At: now})
	if got := judge.Judge("clean").Confidence; got != MaxConfidence {
		t.Fatalf("доверие %d, а потолок %d", got, MaxConfidence)
	}
}

// Старый занос греет слабее свежего, иначе квитанция работает вечно
func TestOldDonationDecays(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	fresh := judgeFrozenAt(now)
	fresh.Donate(Credit{SubjectID: "user-1", AmountMicro: 5_000_000, At: now})

	old := judgeFrozenAt(now)
	old.Donate(Credit{SubjectID: "user-1", AmountMicro: 5_000_000, At: now.Add(-90 * 24 * time.Hour)})

	if old.Credit("user-1") >= fresh.Credit("user-1") {
		t.Fatalf("занос трёхмесячной давности (%.1f) греет не хуже свежего (%.1f)",
			old.Credit("user-1"), fresh.Credit("user-1"))
	}
}

// Заносы переживают выкат: иначе люди платят, а башка забывает
func TestLoadedCreditsSurviveRestart(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	judge := judgeFrozenAt(now)
	judge.LoadCredits([]Credit{
		{SubjectID: "user-1", AmountMicro: 3_000_000, At: now.Add(-time.Hour)},
		{SubjectID: "user-1", AmountMicro: 2_000_000, At: now.Add(-2 * time.Hour)},
	})
	// Пять долларов по два очка за доллар
	if got := judge.Credit("user-1"); got < 9.9 || got > 10.1 {
		t.Fatalf("кредит %.2f, а занесли 5 USDT", got)
	}
}
