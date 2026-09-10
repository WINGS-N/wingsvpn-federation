package domainrules

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

func TestSystemNoiseIsNeverAnAccusation(t *testing.T) {
	noisy := []string{
		"connectivitycheck.gstatic.com",
		"mtalk.google.com",
		"play.googleapis.com",
		"time.android.com",
		"clients3.google.com/generate_204",
		"www.msftconnecttest.com",
	}
	for _, domain := range noisy {
		if !IsSystemNoise(domain) {
			t.Errorf("%q не считается системной вознёй, а телефон ходит туда сам", domain)
		}
	}
	if IsSystemNoise("claude.ai") {
		t.Error("обычный сайт записали в системную возню")
	}
}

func TestBeaconIgnoresTheDeviceTalkingToItself(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	got := Beaconing([]Sighting{{
		SubjectID: "user-1", Domain: "connectivitycheck.gstatic.com",
		Count: 200, UpBytes: 2000, DownBytes: 2000,
		FirstSeen: base, LastSeen: base.Add(6 * time.Hour),
	}})
	if len(got) != 0 {
		t.Fatalf("проверку связности записали в маячки: %+v", got)
	}
}

func TestBeaconCatchesASteadyKnock(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	got := Beaconing([]Sighting{{
		SubjectID: "user-1", Domain: "unknown-c2.example",
		Count: 60, UpBytes: 6000, DownBytes: 6000,
		FirstSeen: base, LastSeen: base.Add(3 * time.Hour),
	}})
	if len(got) != 1 || got[0].Kind != fedpb.AbuseKind_ABUSE_KIND_MALWARE {
		t.Fatalf("ровный стук в неизвестный домен пропустили: %+v", got)
	}
}

func TestBeaconLeavesStreamingAlone(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	got := Beaconing([]Sighting{{
		SubjectID: "user-1", Domain: "video.example",
		Count: 40, DownBytes: 900_000_000, LongLived: 5,
		FirstSeen: base, LastSeen: base.Add(2 * time.Hour),
	}})
	if len(got) != 0 {
		t.Fatalf("кино записали в маячки: %+v", got)
	}
}

func TestClassifyFindsListedDomains(t *testing.T) {
	got := Classify(DefaultRules(), []Sighting{
		{SubjectID: "user-1", Domain: "rutracker.org", Count: 4},
		{SubjectID: "user-1", Domain: "claude.ai", Count: 40},
		{SubjectID: "user-1", Domain: "best-cvvshop.example", Count: 2},
	})
	kinds := map[fedpb.AbuseKind]uint32{}
	for _, v := range got {
		kinds[v.Kind] = v.Count
	}
	if kinds[fedpb.AbuseKind_ABUSE_KIND_TORRENT] != 4 {
		t.Errorf("трекер не опознали: %+v", got)
	}
	if kinds[fedpb.AbuseKind_ABUSE_KIND_MALWARE] != 2 {
		t.Errorf("кардинг-шоп не опознали: %+v", got)
	}
	if len(got) != 2 {
		t.Errorf("обычный сайт попал в обвинение: %+v", got)
	}
}

// Читать новости про копирайт и держать мексиканский поддомен - не нарушение
func TestInnocentNamesAreNotAccused(t *testing.T) {
	innocent := []string{
		"torrentfreak.com",
		"mx.example.com.mx",
		"tracker-analytics.example",
		"fullzoom.example",
	}
	got := Classify(DefaultRules(), sightingsOf(innocent))
	if len(got) != 0 {
		t.Fatalf("невиновных обвинили: %+v", got)
	}
}

// А вот эти узнаются по-прежнему
func TestGuiltyNamesStillMatch(t *testing.T) {
	guilty := []string{"rutracker.org", "torrents.example", "mail.sendgrid.net", "best-cvvshop.example"}
	got := Classify(DefaultRules(), sightingsOf(guilty))
	if len(got) != 3 {
		t.Fatalf("узнали не всё: %+v", got)
	}
}

// Телеметрия ходит ровным ритмом и мелкими ответами, но это не маячок
func TestTelemetryIsNotABeacon(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	for _, domain := range []string{
		"browser-intake-us5-datadoghq.com",
		"sentry.tools.element.io",
		"api.coingecko.com",
		"o123.ingest.sentry.io",
	} {
		got := Beaconing([]Sighting{{
			SubjectID: "user-1", Domain: domain, Count: 90,
			UpBytes: 9000, DownBytes: 9000,
			FirstSeen: base, LastSeen: base.Add(5 * time.Hour),
		}})
		if len(got) != 0 {
			t.Errorf("%s записали в маячки", domain)
		}
	}
}

func sightingsOf(domains []string) []Sighting {
	out := make([]Sighting, 0, len(domains))
	for _, d := range domains {
		out = append(out, Sighting{SubjectID: "user-1", Domain: d, Count: 3})
	}
	return out
}
