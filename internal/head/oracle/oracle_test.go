package oracle

import (
	"strings"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

func judgeAt(t *testing.T, now time.Time) *Judge {
	t.Helper()
	j := NewJudge(NewRulesScorer())
	j.now = func() time.Time { return now }
	return j
}

// A client nobody has complained about starts trusted enough to be served
func TestCleanClientGetsFullBand(t *testing.T) {
	now := time.Now()
	v := judgeAt(t, now).Judge("c1")
	if v.Confidence != StartingConfidence {
		t.Errorf("confidence = %d, want %d", v.Confidence, StartingConfidence)
	}
	if v.Band != BandFull {
		t.Errorf("band = %s, want full", v.Band)
	}
}

// Suspicion should throttle before it bans: most of it is wrong, and a throttle
// is recoverable where a ban is not
func TestSuspicionThrottlesBeforeBanning(t *testing.T) {
	now := time.Now()
	j := judgeAt(t, now)
	// One signal must not be enough: a single observation is usually noise
	j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT, Count: 1, Observed: now})
	if v := j.Judge("c1"); v.Band != BandFull {
		t.Errorf("one signal dropped the band to %s at confidence %d", v.Band, v.Confidence)
	}

	// A real pattern throttles
	for i := 0; i < 2; i++ {
		j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_PORT_SCAN, Count: 1, Observed: now})
	}
	v := j.Judge("c1")
	if v.Band != BandReduced {
		t.Errorf("band = %s at confidence %d, want reduced", v.Band, v.Confidence)
	}

	// Piling on eventually quarantines
	for i := 0; i < 3; i++ {
		j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_MALWARE, Count: 1, Observed: now})
	}
	if v := j.Judge("c1"); v.Band != BandQuarantine {
		t.Errorf("band = %s at confidence %d, want quarantine", v.Band, v.Confidence)
	}
}

// A bad week must stop following somebody around forever
func TestSignalsDecay(t *testing.T) {
	now := time.Now()
	j := judgeAt(t, now)
	old := now.Add(-21 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_PORT_SCAN, Count: 1, Observed: old})
	}
	fresh := judgeAt(t, now)
	for i := 0; i < 3; i++ {
		fresh.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_PORT_SCAN, Count: 1, Observed: now})
	}
	aged := j.Judge("c1")
	recent := fresh.Judge("c1")
	if aged.Confidence <= recent.Confidence {
		t.Errorf("three week old signals (%d) hurt as much as fresh ones (%d)", aged.Confidence, recent.Confidence)
	}
}

// An admin has to be able to answer "why was I cut off"
func TestVerdictExplainsItself(t *testing.T) {
	now := time.Now()
	j := judgeAt(t, now)
	j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT, Count: 2, Observed: now})
	v := j.Judge("c1")
	if len(v.Contributions) == 0 {
		t.Fatal("verdict carried no contributions")
	}
	explain := v.Explain()
	if !strings.Contains(explain, "MAIL_PORT") {
		t.Errorf("explanation does not name the class: %q", explain)
	}
	if v.Scorer != "rules-v1" {
		t.Errorf("scorer = %q, a verdict must say who produced it", v.Scorer)
	}
}

// The whole point of the shadow: compare a new scorer without letting it decide
func TestShadowScorerDecidesNothing(t *testing.T) {
	now := time.Now()
	j := judgeAt(t, now)
	harsh := &RulesScorer{Weights: Weights{fedpb.AbuseKind_ABUSE_KIND_ADS: 200}}
	j.SetShadow(harsh)
	j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_ADS, Count: 1, Observed: now})

	live := j.Judge("c1")
	if live.Band == BandQuarantine {
		t.Error("the shadow scorer changed the live decision")
	}
	shadow, ok := j.Shadow("c1")
	if !ok {
		t.Fatal("no shadow verdict was recorded")
	}
	if shadow.Band != BandQuarantine {
		t.Errorf("shadow band = %s, want quarantine so the comparison is visible", shadow.Band)
	}
}

// Signals are kept as history rather than folded into a counter, because a model
// trained later cannot recover what was discarded
func TestFeaturesAreRetainedForTraining(t *testing.T) {
	now := time.Now()
	j := judgeAt(t, now)
	j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_TORRENT, Count: 1, Observed: now.Add(-time.Hour)})
	j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_ADS, Count: 1, Observed: now})
	features := j.Features("c1")
	if len(features) != 2 {
		t.Fatalf("features = %d, want both signals kept", len(features))
	}
	if !features[0].Observed.Before(features[1].Observed) {
		t.Error("features are not in time order")
	}
}

// History must stay bounded or a busy fleet grows without limit
func TestOldSignalsArePruned(t *testing.T) {
	now := time.Now()
	j := judgeAt(t, now)
	j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_ADS, Count: 1, Observed: now.Add(-60 * 24 * time.Hour)})
	j.Observe(Signal{ClientID: "c1", Kind: fedpb.AbuseKind_ABUSE_KIND_ADS, Count: 1, Observed: now})
	if got := len(j.Features("c1")); got != 1 {
		t.Errorf("features = %d, want the two month old signal pruned", got)
	}
}

func TestBandBoundaries(t *testing.T) {
	cases := map[int]Band{100: BandFull, 60: BandFull, 59: BandReduced, 30: BandReduced, 29: BandQuarantine, 0: BandQuarantine}
	for confidence, want := range cases {
		if got := BandFor(confidence); got != want {
			t.Errorf("BandFor(%d) = %s, want %s", confidence, got, want)
		}
	}
}

// Скорость идёт от самой оценки, а не от полосы: два клиента по разные стороны
// порога не должны получать одно и то же
func TestSpeedFollowsConfidenceNotBand(t *testing.T) {
	lowUp, lowDown := SpeedFor(31)
	highUp, highDown := SpeedFor(59)
	if highUp <= lowUp || highDown <= lowDown {
		t.Fatalf("внутри одной полосы скорость не растёт: %d/%d против %d/%d", lowUp, lowDown, highUp, highDown)
	}

	fullUp, fullDown := SpeedFor(MaxConfidence)
	if fullUp != speedCeilingUplink || fullDown != speedCeilingDownlink {
		t.Fatalf("на полном доверии %d/%d, want %d/%d", fullUp, fullDown, speedCeilingUplink, speedCeilingDownlink)
	}

	floorUp, floorDown := SpeedFor(0)
	if floorUp != speedFloorUplink || floorDown != speedFloorDownlink {
		t.Fatalf("на дне %d/%d, want %d/%d", floorUp, floorDown, speedFloorUplink, speedFloorDownlink)
	}

	// Направления считаются раздельно: канал несимметричен
	if fullUp == fullDown {
		t.Fatal("uplink и downlink совпали - направления не разведены")
	}
}

// Одно срабатывание не должно ронять человека в карантин: у прошлого VPN бывает
// затяжной выход, и минута из двух стран - это не приговор
func TestOneSignalDoesNotQuarantine(t *testing.T) {
	scorer := NewRulesScorer()
	now := time.Now()
	for _, kind := range []fedpb.AbuseKind{
		fedpb.AbuseKind_ABUSE_KIND_GEO_SPREAD,
		fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT,
	} {
		got := scorer.Score("user-1", []Signal{
			{ClientID: "user-1", Kind: kind, Count: 40, Observed: now},
		}, now)
		if got.Band == BandQuarantine {
			t.Fatalf("%v: одно срабатывание отправило в карантин (доверие %d)", kind, got.Confidence)
		}
	}
}

// Повторение обязано топить: разовая случайность прощается, привычка нет
func TestRepeatedSignalsSinkTheScore(t *testing.T) {
	scorer := NewRulesScorer()
	now := time.Now()
	var signals []Signal
	for i := 0; i < 8; i++ {
		signals = append(signals, Signal{
			ClientID: "user-1",
			Kind:     fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT,
			Count:    12,
			Observed: now.Add(-time.Duration(i) * time.Hour),
		})
	}
	if got := scorer.Score("user-1", signals, now); got.Band == BandFull {
		t.Fatalf("восемь срабатываний подряд не тронули доверие: %d", got.Confidence)
	}
}

// Потолок трафика идёт от самой оценки, а не от полосы: иначе человек с 59
// очками и человек с 31 качали бы поровну
func TestQuotaFollowsConfidence(t *testing.T) {
	if QuotaFor(100) != QuotaUnlimited || QuotaFor(fullThreshold) != QuotaUnlimited {
		t.Fatal("чистому человеку выписали потолок")
	}
	if QuotaFor(31) >= QuotaFor(59) {
		t.Fatalf("внутри полосы квота не растёт: %d против %d", QuotaFor(31), QuotaFor(59))
	}
	if QuotaFor(10) != quotaFloorBytes {
		t.Fatal("ниже карантина квота обязана быть полом")
	}
	if QuotaFor(59) == QuotaUnlimited {
		t.Fatal("подозрительный остался без потолка")
	}
}
