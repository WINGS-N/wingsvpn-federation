// Package domainrules превращает наблюдения о доменах в обвинения.
//
// Голые счётчики не значат нихуя: сотня доменов у человека, листающего ленту,
// выглядит ровно как сотня доменов у чекера карт. Отличает их то, КУДА и КАК
// ходят, поэтому разбор идёт по спискам и по форме, а не по объёму
package domainrules

import (
	"strings"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Sighting - свёрнутое наблюдение, как оно пришло с ноды
type Sighting struct {
	SubjectID string
	Domain    string
	Port      uint32
	Count     uint32
	UpBytes   uint64
	DownBytes uint64
	LongLived uint32
	FirstSeen time.Time
	LastSeen  time.Time
}

// systemNoise - домены, куда устройство ходит само, ровным ритмом и без всякого
// участия человека. Проверка связности, пуши, синхронизация времени. Выглядит
// это один в один как маячок малвари, и без списка мы бы обвинили каждый
// телефон в первый же час нахуй
var systemNoise = []string{
	"connectivitycheck.gstatic.com",
	"connectivitycheck.android.com",
	"clients3.google.com",
	"clients4.google.com",
	"www.gstatic.com",
	"mtalk.google.com",
	"android.clients.google.com",
	"play.googleapis.com",
	"play-fe.googleapis.com",
	"firebaseinstallations.googleapis.com",
	"fcmconnection.googleapis.com",
	"time.android.com",
	"time.google.com",
	"pool.ntp.org",
	"captive.apple.com",
	"push.apple.com",
	"gateway.icloud.com",
	"ocsp.digicert.com",
	"ocsp.pki.goog",
	"crl.microsoft.com",
	"www.msftconnecttest.com",
	"dns.msftncsi.com",
	"api.onesignal.com",
	"cdn.samsungcloudsolution.com",
	"connectivity.samsungcloudsolution.com",
}

// telemetry - сбор ошибок, аналитика и опрос котировок. Долбится ровным ритмом,
// мелкими ответами, часами подряд, то есть выглядит точь-в-точь как управляющий
// канал. Без списка маячок выебет любого, у кого приложение шлёт крашлоги
var telemetry = []string{
	"sentry.io",
	"ingest.sentry.io",
	"datadoghq.com",
	"browser-intake-datadoghq.com",
	"newrelic.com",
	"nr-data.net",
	"bugsnag.com",
	"crashlytics.com",
	"firebase-settings.crashlytics.com",
	"app-measurement.com",
	"google-analytics.com",
	"analytics.google.com",
	"googletagmanager.com",
	"amplitude.com",
	"mixpanel.com",
	"segment.io",
	"posthog.com",
	"appcenter.ms",
	"api.coingecko.com",
	"api.binance.com",
	"stream.binance.com",
}

// noisePaths - куски пути, по которым узнаётся проверка связности у кого угодно.
// Домен тут не поможет, потому что таких хостов десятки
var noisePaths = []string{"generate_204", "ncsi.txt", "hotspot-detect"}

// IsSystemNoise говорит, что домен - это фоновая возня устройства, а не выбор
// человека. Такие обращения из разбора выкидываются целиком
func IsSystemNoise(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return true
	}
	for _, known := range systemNoise {
		if d == known || strings.HasSuffix(d, "."+known) {
			return true
		}
	}
	for _, known := range telemetry {
		if d == known || strings.HasSuffix(d, "."+known) {
			return true
		}
	}
	// Поддомен сбора ошибок бывает чей угодно, а не только вендорский
	for _, part := range []string{"sentry.", "-intake-", "telemetry.", "analytics."} {
		if strings.Contains(d, part) {
			return true
		}
	}
	for _, part := range noisePaths {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}

// Rule - один список доменов и класс, который он означает
type Rule struct {
	Kind   fedpb.AbuseKind
	Suffix []string
	Exact  []string
	// Prefix бьёт по началу имени. Нужен там, где подстрока ловит невиновных,
	// а имя всё же узнаваемо
	Prefix  []string
	Keyword []string
}

// Matches проверяет домен по одному правилу
func (r Rule) Matches(domain string) bool {
	for _, exact := range r.Exact {
		if domain == exact {
			return true
		}
	}
	for _, suffix := range r.Suffix {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	for _, prefix := range r.Prefix {
		if strings.HasPrefix(domain, prefix) {
			return true
		}
	}
	for _, word := range r.Keyword {
		if strings.Contains(domain, word) {
			return true
		}
	}
	return false
}

// DefaultRules - стартовый набор. На полноту не претендует ни разу, он тут
// чтобы механика работала с первого дня, а пополняться будет из фидов
func DefaultRules() []Rule {
	return []Rule{
		{
			Kind: fedpb.AbuseKind_ABUSE_KIND_TORRENT,
			Suffix: []string{
				"rutracker.org", "nnmclub.to", "thepiratebay.org", "1337x.to",
				"rutor.info", "kinozal.tv", "torrentgalaxy.to", "yts.mx",
			},
			// Только начало имени: "tracker." сидит в куче аналитики, а
			// "torrent" внутри слова ловит новостные сайты про копирайт
			Prefix: []string{"tracker.", "torrent.", "torrents."},
		},
		{
			Kind: fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT,
			// Только площадки массовой рассылки. Класс про спам, а не про
			// доступ к почте: под "mail." и "mx." попадает и обычный почтовик,
			// и человек, который просто открыл свой ящик
			Suffix: []string{
				"smtp.com", "sendgrid.net", "mailgun.org", "mandrillapp.com",
				"sparkpostmail.com", "amazonses.com", "elasticemail.com",
				"smtp2go.com", "mailchimp.com", "sendpulse.com",
			},
		},
		{
			Kind: fedpb.AbuseKind_ABUSE_KIND_MALWARE,
			// Кардинг и фишинг идут сюда же: класс говорит "мошенничество", а
			// не "вирус", и разводить их отдельными полосами смысла нет
			// Слова длинные нарочно: короткое "fullz" сидит внутри "fullzoom",
			// и обвинять по подстроке в три-пять букв значит ловить невиновных
			Keyword: []string{
				"ccshop", "dumpsshop", "cvvshop", "carding",
				"combolist", "checkercc", "bruteforce",
			},
		},
	}
}

// Verdict - что разбор надумал по одному субъекту
type Verdict struct {
	SubjectID string
	Kind      fedpb.AbuseKind
	Count     uint32
	// Domains - что именно сработало. Нужен для ответа на вопрос "за что", в
	// сигнал наверх не уходит
	Domains []string
	// Why - человеческое объяснение от разбора по форме
	Why string
}

// Feed - чужой список плохих доменов. Ложится рядом со своими правилами: список
// знает про уже спалившееся, правила и разбор по форме ловят то, чего в списках
// ещё нет
type Feed interface {
	Kind(domain string) (fedpb.AbuseKind, bool)
}

// Classify разбирает наблюдения субъекта и возвращает обвинения по классам
func Classify(rules []Rule, sightings []Sighting) []Verdict {
	return ClassifyWithFeed(rules, nil, sightings)
}

// ClassifyWithFeed - то же самое, но со сверкой по чужому списку
func ClassifyWithFeed(rules []Rule, feed Feed, sightings []Sighting) []Verdict {
	hits := map[fedpb.AbuseKind]*Verdict{}
	add := func(subjectID string, kind fedpb.AbuseKind, count uint32, domain string) {
		entry, ok := hits[kind]
		if !ok {
			entry = &Verdict{SubjectID: subjectID, Kind: kind}
			hits[kind] = entry
		}
		entry.Count += count
		if len(entry.Domains) < 16 {
			entry.Domains = append(entry.Domains, domain)
		}
	}
	for _, s := range sightings {
		domain := strings.ToLower(strings.TrimSpace(s.Domain))
		if IsSystemNoise(domain) {
			continue
		}
		if feed != nil {
			if kind, listed := feed.Kind(domain); listed {
				add(s.SubjectID, kind, s.Count, domain)
			}
		}
		for _, rule := range rules {
			if !rule.Matches(domain) {
				continue
			}
			add(s.SubjectID, rule.Kind, s.Count, domain)
		}
	}
	out := make([]Verdict, 0, len(hits))
	for _, v := range hits {
		out = append(out, *v)
	}
	return out
}

// beaconMinHits - сколько обращений нужно, чтобы говорить о ритме. Меньше
// десятка это не ритм, а совпадение
const beaconMinHits = 12

// beaconMaxBytesPerHit - маячок носит команду, а не данные. Килобайт на
// обращение это уже нормальный обмен, а не стук "я живой"
const beaconMaxBytesPerHit = 2048

// Beaconing ищет ровный стук в незнакомый домен.
//
// Живой человек ходит рвано: открыл, почитал, закрыл. А ровный ритм с крошечным
// ответом - это управляющий канал. Системная возня телефона выглядит так же,
// поэтому её вырезаем списком ДО разбора, иначе обвиним всех подряд
func Beaconing(sightings []Sighting) []Verdict {
	var out []Verdict
	for _, s := range sightings {
		if IsSystemNoise(s.Domain) || s.Count < beaconMinHits {
			continue
		}
		// Долгие соединения это поток, а не стук
		if s.LongLived > 0 {
			continue
		}
		total := s.UpBytes + s.DownBytes
		if total/uint64(s.Count) > beaconMaxBytesPerHit {
			continue
		}
		// Ритм: обращения размазаны по времени, а не свалены в одну секунду
		if s.LastSeen.Sub(s.FirstSeen) < 10*time.Minute {
			continue
		}
		out = append(out, Verdict{
			SubjectID: s.SubjectID,
			Kind:      fedpb.AbuseKind_ABUSE_KIND_MALWARE,
			Count:     s.Count,
			Domains:   []string{s.Domain},
		})
	}
	return out
}
