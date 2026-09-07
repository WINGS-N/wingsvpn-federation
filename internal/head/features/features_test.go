package features

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

func at(hour int) time.Time {
	return time.Date(2026, 9, 2, hour, 0, 0, 0, time.UTC)
}

// Обычный человек не должен задеть ни одного правила
func TestAnOrdinaryEveningIsClean(t *testing.T) {
	sightings := []Sighting{
		{Domain: "claude.ai", Port: 443, Count: 40, DownBytes: 12_000_000, UpBytes: 400_000, LongLived: 4, At: at(19)},
		{Domain: "matrix.wingsnet.org", Port: 443, Count: 30, DownBytes: 3_000_000, UpBytes: 300_000, LongLived: 2, At: at(20)},
		{Domain: "www.google.com", Port: 443, Count: 20, DownBytes: 2_000_000, UpBytes: 100_000, At: at(21)},
	}
	v := Build("user-1", time.Hour, sightings, nil)
	if got := Judge(v); len(got) != 0 {
		t.Fatalf("обычный вечер записали в нарушения: %+v (вектор %+v)", got, v)
	}
}

func TestACheckerLooksNothingLikeAPerson(t *testing.T) {
	var sightings []Sighting
	for i := 0; i < 400; i++ {
		sightings = append(sightings, Sighting{
			Domain: domainNo(i), Port: 443, Count: 1,
			DownBytes: 300, UpBytes: 200, At: at(3),
		})
	}
	v := Build("user-2", time.Hour, sightings, nil)
	found := kinds(Judge(v))
	if !found[fedpb.AbuseKind_ABUSE_KIND_PORT_SCAN] {
		t.Fatalf("перебор по сотням имён не опознали: %+v", v)
	}
}

// Много писем через ОДИН сервер - это человек с почтой, а не спамер
func TestOneMailServerIsNotSpam(t *testing.T) {
	v := Build("user-3", time.Hour, []Sighting{
		{Domain: "relay.unknown.example", Port: 587, Count: 90, UpBytes: 900_000, At: at(12)},
	}, nil)
	if kinds(Judge(v))[fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT] {
		t.Fatalf("отправку через свой сервер записали в рассылку: %+v", v)
	}
}

func TestBareAddressSwarmIsTorrent(t *testing.T) {
	v := Build("user-4", time.Hour, nil, []PortHit{
		{Port: 51413, Count: 900, DistinctTargets: 300, UpBytes: 900_000_000, DownBytes: 900_000_000},
	})
	if !kinds(Judge(v))[fedpb.AbuseKind_ABUSE_KIND_TORRENT] {
		t.Fatalf("рой пиров на голых адресах пропустили: %+v", v)
	}
}

func TestGeneratedNamesAreSpottedByShape(t *testing.T) {
	generated := []string{
		"kqxvbzrtnwpl", "xz8k2mqp7vwn", "bvkxzmqpwrtz", "zxqvbnmkwrtp",
		"qzwxrtvbnmkp", "mkqzxvbnwrtp", "vbnmqzxwrtkp", "wrtpqzxvbnmk",
	}
	for _, name := range generated {
		if !LooksGenerated(name + ".example") {
			t.Errorf("%q не опознали как сгенерированное", name)
		}
	}
	for _, name := range []string{
		"claude.ai", "matrix.wingsnet.org", "api.coingecko.com",
		"www.internet.apps.samsung.com", "content-autofill.googleapis.com",
	} {
		if LooksGenerated(name) {
			t.Errorf("живое имя %q записали в сгенерированные", name)
		}
	}
}

func TestTooLittleTrafficIsNotJudged(t *testing.T) {
	v := Build("user-5", time.Hour, []Sighting{
		{Domain: "relay.example", Port: 587, Count: 3, At: at(12)},
	}, nil)
	if got := Judge(v); len(got) != 0 {
		t.Fatalf("судят по трём обращениям: %+v", got)
	}
}

func kinds(findings []Finding) map[fedpb.AbuseKind]bool {
	out := map[fedpb.AbuseKind]bool{}
	for _, f := range findings {
		out[f.Kind] = true
	}
	return out
}

func domainNo(i int) string {
	letters := "abcdefghijklmnopqrstuvwxyz"
	return string(letters[i%26]) + string(letters[(i/26)%26]) + string(letters[(i/676)%26]) + "-shop.example"
}

// Человек с настроенной почтой ходит на 587 каждый день, и это не рассылка
func TestOrdinaryMailClientIsNotSpam(t *testing.T) {
	v := Build("user-6", time.Hour, []Sighting{
		{Domain: "smtp.yandex.ru", Port: 587, Count: 80, UpBytes: 400_000, DownBytes: 100_000, At: at(9)},
		{Domain: "imap.yandex.ru", Port: 993, Count: 200, DownBytes: 8_000_000, LongLived: 3, At: at(9)},
	}, nil)
	if kinds(Judge(v))[fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT] {
		t.Fatalf("человека с почтовым клиентом обвинили в рассылке: %+v", v)
	}
}

// А вот исходящие на 25 порт - это уже не клиент
func TestRelayPortIsAlwaysSuspicious(t *testing.T) {
	v := Build("user-7", time.Hour, nil, []PortHit{
		{Port: 25, Count: 200, DistinctTargets: 150, UpBytes: 2_000_000},
	})
	if !kinds(Judge(v))[fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT] {
		t.Fatalf("рассылку через 25 порт пропустили: %+v", v)
	}
}

// Рассылка через десятки чужих релеев видна по разбросу серверов
func TestSubmissionAcrossManyRelaysIsSpam(t *testing.T) {
	v := Build("user-8", time.Hour, nil, []PortHit{
		{Port: 587, Count: 400, DistinctTargets: 60, UpBytes: 5_000_000},
	})
	if !kinds(Judge(v))[fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT] {
		t.Fatalf("рассылку по чужим релеям пропустили: %+v", v)
	}
}
