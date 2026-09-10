// Package features считает по субъекту числа, на которых можно судить.
//
// Списки доменов обходятся за пять минут: поднял свой домен и ты невидим нахуй.
// А вот ФОРМУ поведения хер подделаешь, потому что она и есть сама работа.
// Здесь сырьё перемалывается в вектор, который одинаково жрут и правила, и
// модель, и внешний разбор - это и есть та дырка, куда втыкается ML
package features

import (
	"math"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Version - набор признаков. Дёргается, когда признаки меняют смысл: иначе в
// обучение попадёт мешанина из двух разных наборов и модель будет судить по
// мусору, никому об этом не сказав
const Version = "features-v2"

// Sighting - наблюдение по домену, как оно лежит в базе
type Sighting struct {
	Domain    string
	Port      uint32
	Count     uint32
	UpBytes   uint64
	DownBytes uint64
	LongLived uint32
	At        time.Time
}

// PrintHit - отпечаток TLS-стека и сколько соединений через него прошло
type PrintHit struct {
	JA4   string
	Count uint32
}

// PortHit - соединения без домена, сведённые по порту
type PortHit struct {
	Port            uint32
	Count           uint32
	DistinctTargets uint32
	UpBytes         uint64
	DownBytes       uint64
}

// Vector - то, что видит скорер. Только числа и ни одной строки: имя домена в
// признаке означает, что модель выучит список, а не поведение, и грош ей тогда
// цена
type Vector struct {
	SubjectID string
	Window    time.Duration

	// Requests - всего обращений, Domains - сколько разных имён
	Requests uint64
	Domains  int
	// DomainsPerHour - скорость появления новых имён. Человек листает десятки,
	// а чекер молотит сотни и остановиться не может
	DomainsPerHour float64
	// BytesPerRequest - средний размер обмена. При переборе крохи, при обычном
	// просмотре жирные куски
	BytesPerRequest float64
	// UpRatio - доля отдачи. У раздачи и рассылки её перекашивает вверх
	UpRatio float64
	// LongLivedShare - доля долгих соединений. У живого человека хоть одно да
	// найдётся, у перебора нет ни единого
	LongLivedShare float64
	// QuietHours - самая длинная пауза в сутках, ActiveHours - сколько часов
	// задето. Считаются впрок, для суточного разбора и обучения: по ним НЕЛЬЗЯ
	// судить на коротком окне, а полного затишья не бывает вообще ни у кого,
	// потому что телефон ночью сам ходит за пушами, а туннель держат постоянно
	QuietHours  float64
	ActiveHours int
	// SpreadHours - на сколько часов размазана активность
	SpreadHours float64
	// RandomNameShare - доля сгенерированных имён, считанная по владельцам имён,
	// а не по самим именам. CDN раздаёт человеку десятки шардов одного домена,
	// и по полным именам такой человек выглядел бы генератором
	RandomNameShare float64
	// RandomNameOwners - у скольких разных владельцев имена похожи на
	// сгенерированные. Малварь перебирает домены, а не поддомены одного
	RandomNameOwners int
	// Owners - сколько всего владельцев имён видно. На горстке имён доля ничего
	// не значит: три странных хоста из двенадцати это четверть на ровном месте
	Owners int
	// randomOwners - те же владельцы поимённо, чтобы AddDomainAges вычеркнул
	// тех, кто зарегистрирован годы назад
	randomOwners map[string]struct{}
	// NoDomainShare - доля соединений на голый адрес
	NoDomainShare float64
	// RelayPortHits - обращения на порт между почтовыми серверами
	RelayPortHits uint64
	// SubmissionHits - отправка почты из клиентской программы, сама по себе
	// обычное дело
	SubmissionHits uint64
	// SubmissionTargets - на скольких разных серверах эта отправка. Один-два
	// это свой ящик, десятки это рассылка по чужим релеям
	SubmissionTargets uint32
	// PeerPortHits - обращения на диапазон bittorrent
	PeerPortHits uint64
	// DistinctBarePeers - сколько разных адресов без домена
	DistinctBarePeers uint32
	// PortsTouched - сколько разных портов задето. Скан виден именно здесь
	PortsTouched int
	// DistinctPrints - сколько разных TLS-стеков лезло наружу под этим
	// профилем. Через туннель прёт весь телефон, поэтому пара-тройка это норма
	// (браузер, системный стек, что-то со своим), а вот десяток значит, что за
	// одной ссылкой сидит толпа
	DistinctPrints int
	// TopPrintShare - доля самого частого стека. У одного человека почти всё
	// уходит через системный, у расшаренной ссылки доли размазаны
	TopPrintShare float64
	// FreshDomains - сколько разных имён моложе месяца, FreshDomainShare - их
	// доля среди тех, чей возраст мы вообще знаем. Считать долю от ВСЕХ имён
	// нельзя нахуй: половина зон RDAP не держит, и незнание превратилось бы в
	// обвинение
	FreshDomains     int
	FreshDomainShare float64
}

// relayPort - порт между почтовыми серверами. Клиентские программы туда не
// суются, операторы его режут, так что исходящее соединение на него это почти
// всегда рассылка спама
const relayPort = 25

// submissionPorts - порты, которыми человек отправляет почту из своей программы.
// Сами по себе они норма: настроенный на телефоне ящик ходит туда каждый день.
// Подозрительной их делает только россыпь разных серверов
var submissionPorts = map[uint32]bool{465: true, 587: true, 2525: true}

// AddDomainAges досыпает в вектор возраст доменов.
//
// Отдельным шагом, а не внутри Build: возраст приезжает из реестра, это поход в
// сеть, и тащить его в чистый счётчик значило бы намертво связать разбор с
// доступностью чужого сервиса. Не ответили - признак остаётся пустым, и по нему
// просто не судят
func (v *Vector) AddDomainAges(freshDays float64, ages map[string]float64) {
	var known, fresh int
	for _, days := range ages {
		known++
		if days <= freshDays {
			fresh++
		}
	}
	v.FreshDomains = fresh
	if known > 0 {
		v.FreshDomainShare = float64(fresh) / float64(known)
	}
	// Реестр знает возраст - значит про форму имени можно забыть: шарды CDN
	// сидят на доменах, которым годы, и генератором их считать не за что
	for host, days := range ages {
		if days <= matureDomainDays {
			continue
		}
		delete(v.randomOwners, DomainOwner(host))
	}
	v.countRandom()
}

// countRandom пересчитывает долю сгенерированных имён по владельцам
func (v *Vector) countRandom() {
	v.RandomNameOwners = len(v.randomOwners)
	v.RandomNameShare = 0
	if v.Owners > 0 {
		v.RandomNameShare = float64(len(v.randomOwners)) / float64(v.Owners)
	}
}

// matureDomainDays - с какого возраста имя перестаёт быть подозрительным по
// форме. Генератор живёт неделями: домен, которому годы, был заведён человеком,
// как бы дико ни выглядела метка перед ним
const matureDomainDays = 180

// Build сводит наблюдения субъекта в вектор
func Build(subjectID string, window time.Duration, sightings []Sighting, ports []PortHit) Vector {
	return BuildWithPrints(subjectID, window, sightings, ports, nil)
}

// BuildWithPrints - тот же вектор вместе с отпечатками клиента
func BuildWithPrints(subjectID string, window time.Duration, sightings []Sighting, ports []PortHit, prints []PrintHit) Vector {
	v := build(subjectID, window, sightings, ports)
	var total, top uint64
	seen := map[string]struct{}{}
	for _, p := range prints {
		if p.JA4 == "" {
			continue
		}
		hits := uint64(p.Count)
		if hits == 0 {
			hits = 1
		}
		seen[p.JA4] = struct{}{}
		total += hits
		if hits > top {
			top = hits
		}
	}
	v.DistinctPrints = len(seen)
	if total > 0 {
		v.TopPrintShare = float64(top) / float64(total)
	}
	return v
}

func build(subjectID string, window time.Duration, sightings []Sighting, ports []PortHit) Vector {
	v := Vector{SubjectID: subjectID, Window: window}

	names := map[string]struct{}{}
	touched := map[uint32]struct{}{}
	var bytes, up uint64
	var longLived uint64
	hours := map[int]bool{}
	owners := map[string]struct{}{}
	randomOwners := map[string]struct{}{}
	var first, last time.Time

	for _, s := range sightings {
		hits := uint64(s.Count)
		if hits == 0 {
			hits = 1
		}
		v.Requests += hits
		bytes += s.UpBytes + s.DownBytes
		up += s.UpBytes
		longLived += uint64(s.LongLived)
		if _, seen := names[s.Domain]; !seen {
			names[s.Domain] = struct{}{}
			owner := DomainOwner(s.Domain)
			if owner != "" {
				owners[owner] = struct{}{}
				if LooksGenerated(s.Domain) {
					randomOwners[owner] = struct{}{}
				}
			}
		}
		if s.Port != 0 {
			touched[s.Port] = struct{}{}
			switch {
			case s.Port == relayPort:
				v.RelayPortHits += hits
			case submissionPorts[s.Port]:
				v.SubmissionHits += hits
				v.SubmissionTargets++
			}
		}
		if !s.At.IsZero() {
			hours[s.At.UTC().Hour()] = true
		}
		if first.IsZero() || s.At.Before(first) {
			first = s.At
		}
		if s.At.After(last) {
			last = s.At
		}
	}

	var bareHits uint64
	for _, p := range ports {
		hits := uint64(p.Count)
		if hits == 0 {
			hits = 1
		}
		bareHits += hits
		v.Requests += hits
		bytes += p.UpBytes + p.DownBytes
		up += p.UpBytes
		v.DistinctBarePeers += p.DistinctTargets
		if p.Port != 0 {
			touched[p.Port] = struct{}{}
			switch {
			case p.Port == relayPort:
				v.RelayPortHits += hits
			case submissionPorts[p.Port]:
				v.SubmissionHits += hits
				v.SubmissionTargets += p.DistinctTargets
			}
			if p.Port >= 6881 && p.Port <= 6999 {
				v.PeerPortHits += hits
			}
		}
	}

	v.Domains = len(names)
	v.PortsTouched = len(touched)
	if v.Requests > 0 {
		v.BytesPerRequest = float64(bytes) / float64(v.Requests)
		v.LongLivedShare = float64(longLived) / float64(v.Requests)
		v.NoDomainShare = float64(bareHits) / float64(v.Requests)
	}
	if bytes > 0 {
		v.UpRatio = float64(up) / float64(bytes)
	}
	v.Owners = len(owners)
	v.randomOwners = randomOwners
	v.countRandom()
	if !first.IsZero() && last.After(first) {
		v.SpreadHours = last.Sub(first).Hours()
	}
	perHour := v.SpreadHours
	if perHour < 1 {
		perHour = 1
	}
	v.DomainsPerHour = float64(v.Domains) / perHour
	v.ActiveHours = len(hours)
	v.QuietHours = longestQuiet(hours)
	return v
}

// longestQuiet ищет самый длинный промежуток суток без единого обращения.
//
// Циклически, потому что сон через полночь это тоже сон, а разрезать сутки по
// UTC значило бы наказывать всех, кто живёт не в Гринвиче
func longestQuiet(hours map[int]bool) float64 {
	if len(hours) == 0 {
		return 24
	}
	if len(hours) == 24 {
		return 0
	}
	best, run := 0, 0
	// Два круга по суткам: так пауза, переходящая через полночь, считается
	// одним куском, а не двумя огрызками
	for i := 0; i < 48; i++ {
		if hours[i%24] {
			run = 0
			continue
		}
		run++
		if run > best {
			best = run
		}
	}
	if best > 24 {
		best = 24
	}
	return float64(best)
}

// commonWords - куски, которые встречаются в живых именах. Домен с ними почти
// наверняка писал человек, даже если выглядит он как ебанина
var commonWords = []string{
	"api", "cdn", "www", "mail", "static", "img", "media", "cloud", "app",
	"shop", "news", "video", "auth", "login", "chat", "play", "google",
	"yandex", "samsung", "apple", "micro", "soft", "tube", "gram", "bank",
}

// LooksGenerated говорит, что имя высрано генератором, а не придумано.
//
// Считается по форме, а не по списку: у алгоритмических имён высокая энтропия,
// длинная метка и ни одного узнаваемого куска. Так ловятся управляющие домены,
// которых нет и не будет ни в одном фиде, потому что их наплодили час назад
func LooksGenerated(domain string) bool {
	label := firstLabel(domain)
	if len(label) < 10 {
		return false
	}
	for _, word := range commonWords {
		if strings.Contains(label, word) {
			return false
		}
	}
	if entropy(label) < 3.2 {
		return false
	}
	return vowelShare(label) < 0.26 || digitShare(label) > 0.3
}

// DomainOwner - имя, за которым стоит один владелец: домен на уровень ниже
// публичного суффикса. Без него шарды одного CDN считаются разными хозяевами
func DomainOwner(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return ""
	}
	owner, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return d
	}
	return owner
}

func firstLabel(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if idx := strings.Index(domain, "."); idx > 0 {
		return domain[:idx]
	}
	return domain
}

// entropy - энтропия Шеннона по символам, в битах
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	total := float64(len([]rune(s)))
	out := 0.0
	for _, n := range counts {
		p := n / total
		out -= p * math.Log2(p)
	}
	return out
}

func vowelShare(s string) float64 {
	if s == "" {
		return 0
	}
	vowels := 0
	for _, r := range s {
		if strings.ContainsRune("aeiouy", r) {
			vowels++
		}
	}
	return float64(vowels) / float64(len([]rune(s)))
}

func digitShare(s string) float64 {
	if s == "" {
		return 0
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return float64(digits) / float64(len([]rune(s)))
}

// Names перечисляет признаки в устойчивом порядке. Нужно и для обучения, и для
// того, чтобы вектор можно было положить в строку журнала, не гадая о порядке
func Names() []string {
	names := []string{
		"requests", "domains", "domains_per_hour", "bytes_per_request",
		"up_ratio", "long_lived_share", "quiet_hours", "active_hours", "spread_hours",
		"random_name_share", "no_domain_share", "relay_port_hits",
		"submission_hits", "submission_targets",
		"peer_port_hits", "distinct_bare_peers", "ports_touched",
		"distinct_prints", "top_print_share",
		"fresh_domains", "fresh_domain_share",
	}
	sort.Strings(names)
	return names
}

// Values отдаёт вектор числами в порядке Names
func (v Vector) Values() map[string]float64 {
	return map[string]float64{
		"requests":            float64(v.Requests),
		"domains":             float64(v.Domains),
		"domains_per_hour":    v.DomainsPerHour,
		"bytes_per_request":   v.BytesPerRequest,
		"up_ratio":            v.UpRatio,
		"long_lived_share":    v.LongLivedShare,
		"quiet_hours":         v.QuietHours,
		"active_hours":        float64(v.ActiveHours),
		"spread_hours":        v.SpreadHours,
		"random_name_share":   v.RandomNameShare,
		"no_domain_share":     v.NoDomainShare,
		"relay_port_hits":     float64(v.RelayPortHits),
		"submission_hits":     float64(v.SubmissionHits),
		"submission_targets":  float64(v.SubmissionTargets),
		"peer_port_hits":      float64(v.PeerPortHits),
		"distinct_bare_peers": float64(v.DistinctBarePeers),
		"ports_touched":       float64(v.PortsTouched),
		"distinct_prints":     float64(v.DistinctPrints),
		"top_print_share":     v.TopPrintShare,
		"fresh_domains":       float64(v.FreshDomains),
		"fresh_domain_share":  v.FreshDomainShare,
	}
}
