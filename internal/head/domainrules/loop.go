package domainrules

import (
	"context"
	"strings"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/features"
)

// Every - как часто разбирается накопленное. Домены сворачиваются на ноде за
// минуту, так что разбирать чаще нечего, а реже значит дольше держать
// мошенника с полным доступом
const Every = 10 * time.Minute

// batchLimit ограничивает один круг. Флот может насыпать сколько угодно, а
// подавиться на старте после простоя нам незачем
const batchLimit = 20000

// Source отдаёт наблюдения, пришедшие после отметки
type Source interface {
	Fresh(since time.Time, limit int) ([]Sighting, error)
	FreshPorts(since time.Time, limit int) ([]SubjectPorts, error)
	FreshPrints(since time.Time, limit int) ([]SubjectPrint, error)
}

// SubjectPorts - соединения без домена, привязанные к участнику
type SubjectPorts struct {
	SubjectID string
	Hit       features.PortHit
}

// SubjectPrint - отпечаток TLS-стека, привязанный к участнику
type SubjectPrint struct {
	SubjectID string
	Hit       features.PrintHit
}

// VectorScorer - точка, куда втыкается модель.
//
// Правила считают по порогам и объясняют себя формулой, модель считает по всему
// вектору сразу и ловит то, под что порог не напишешь. Реализация живёт РЯДОМ с
// правилами, а не вместо них, и по умолчанию работает в тени: её вердикт
// логируется, но никого не отрезает, пока ей не начнут доверять
type VectorScorer interface {
	Name() string
	// ScoreVector отдаёт находки по вектору. Ошибка не беда, разбор идёт
	// дальше на правилах
	ScoreVector(ctx context.Context, v features.Vector) ([]features.Finding, error)
}

// Accuser принимает обвинение. Тот же вход, что у сигналов с ноды: разбор на
// башке это ещё один источник, а не отдельная ветка правосудия
type Accuser func(signal *fedpb.AbuseSignal, nodeID string)

// Loop гоняет разбор по расписанию
type Loop struct {
	source Source
	accuse Accuser
	rules  []Rule
	mark   time.Time
	log    func(string, ...any)
	// model решает вместе с правилами, когда ей доверяют, и молча считает
	// рядом, когда ещё нет
	model VectorScorer
	// modelShadow держит модель в тени: считает и пишет в журнал, но обвинения
	// от неё наверх не уходят
	modelShadow bool
	// recorder копит векторы. Без накопления учить будет не на чем, а задним
	// числом вектор из готового вердикта уже хуй восстановишь
	recorder Recorder
	// ages узнаёт возраст доменов. Необязателен: без него признак свежести
	// остаётся пустым, и по нему просто никто не судит
	ages Ages
	// feed - чужие списки. Тоже необязателен: не завели или источник лежит -
	// разбор идёт на своих правилах и на форме поведения
	feed Feed
}

// SetFeed включает сверку по чужим спискам
func (l *Loop) SetFeed(feed Feed) { l.feed = feed }

// Ages отдаёт возраст домена в днях. Второе значение false означает "хуй знает"
type Ages interface {
	StartRound()
	AgeDays(ctx context.Context, domain string) (float64, bool)
}

// SetAges включает разбор по возрасту доменов
func (l *Loop) SetAges(ages Ages) { l.ages = ages }

// SetModel подключает модель. shadow=true означает "считай и молчи"
func (l *Loop) SetModel(model VectorScorer, shadow bool) {
	l.model, l.modelShadow = model, shadow
}

func NewLoop(source Source, accuse Accuser, log func(string, ...any)) *Loop {
	return &Loop{source: source, accuse: accuse, rules: DefaultRules(), mark: time.Now().UTC(), log: log}
}

// Run разбирает, пока жив ctx
func (l *Loop) Run(ctx context.Context) {
	ticker := time.NewTicker(Every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.Once()
		}
	}
}

// Once - один круг разбора
func (l *Loop) Once() {
	sightings, err := l.source.Fresh(l.mark, batchLimit)
	if err != nil {
		if l.log != nil {
			l.log("domainrules: fresh observations unreadable: %v", err)
		}
		return
	}
	if len(sightings) == 0 {
		return
	}
	for _, s := range sightings {
		if s.LastSeen.After(l.mark) {
			l.mark = s.LastSeen
		}
	}
	bySubject := map[string][]Sighting{}
	for _, s := range sightings {
		bySubject[s.SubjectID] = append(bySubject[s.SubjectID], s)
	}
	if l.ages != nil {
		l.ages.StartRound()
	}
	ports, err := l.source.FreshPorts(l.mark, batchLimit)
	if err != nil && l.log != nil {
		l.log("domainrules: port observations unreadable: %v", err)
	}
	portsBySubject := map[string][]features.PortHit{}
	for _, p := range ports {
		portsBySubject[p.SubjectID] = append(portsBySubject[p.SubjectID], p.Hit)
	}
	prints, err := l.source.FreshPrints(l.mark, batchLimit)
	if err != nil && l.log != nil {
		l.log("domainrules: tls fingerprints unreadable: %v", err)
	}
	printsBySubject := map[string][]features.PrintHit{}
	for _, p := range prints {
		printsBySubject[p.SubjectID] = append(printsBySubject[p.SubjectID], p.Hit)
	}
	for subject := range portsBySubject {
		if _, ok := bySubject[subject]; !ok {
			bySubject[subject] = nil
		}
	}
	for subject := range printsBySubject {
		if _, ok := bySubject[subject]; !ok {
			bySubject[subject] = nil
		}
	}

	for subject, own := range bySubject {
		verdicts := append(ClassifyWithFeed(l.rules, l.feed, own), Beaconing(own)...)
		// Разбор по форме идёт рядом со списками: список обходится своим
		// доменом, а форму поведения подделать нельзя, не перестав нарушать
		vector := features.BuildWithPrints(subject, Every, featureSightings(own), portsBySubject[subject], printsBySubject[subject])
		vector.AddDomainAges(features.FreshDomainDays, l.domainAges(own))
		for _, f := range features.Judge(vector) {
			verdicts = append(verdicts, Verdict{SubjectID: subject, Kind: f.Kind, Count: f.Count, Why: f.Why})
		}
		verdicts = append(verdicts, l.askModel(subject, vector)...)
		if l.recorder != nil {
			// Обвинение от правил - это готовая метка, и притом надёжная:
			// порог не плавает от прогона к прогону, в отличие от модели
			label, by := int16(LabelUnknown), ""
			if len(verdicts) > 0 {
				label, by = 1, LabelByRules
			}
			if err := l.recorder.PutSnapshot(subject, time.Now().UTC(), features.Version, vector.Values(), label, by); err != nil && l.log != nil {
				l.log("domainrules: snapshot not stored for %s: %v", subject, err)
			}
		}
		for _, v := range verdicts {
			l.accuse(&fedpb.AbuseSignal{
				ProfileId: subject,
				Kind:      v.Kind,
				Count:     v.Count,
				// Окно совпадает с кругом разбора: башка взвешивает всплеск
				// иначе, чем ровный фон
				WindowSeconds: uint32(Every.Seconds()),
			}, "")
			if l.log != nil {
				l.log("domainrules: %s accused of %s over %d hits", subject, v.Kind, v.Count)
			}
		}
	}
}

// domainAges узнаёт возраст доменов субъекта. Системную возню телефона не
// спрашиваем вовсе: она и так вычеркнута из разбора, а запросы в реестр не
// бесплатные
func (l *Loop) domainAges(own []Sighting) map[string]float64 {
	if l.ages == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), agesTimeout)
	defer cancel()
	out := map[string]float64{}
	for _, s := range own {
		domain := strings.ToLower(strings.TrimSpace(s.Domain))
		if domain == "" || IsSystemNoise(domain) {
			continue
		}
		if _, seen := out[domain]; seen {
			continue
		}
		if days, ok := l.ages.AgeDays(ctx, domain); ok {
			out[domain] = days
		}
	}
	return out
}

// agesTimeout - сколько всего ждём реестры за одного субъекта. Разбор идёт по
// расписанию, и залипнуть на чужом молчащем сервисе он права не имеет
const agesTimeout = 30 * time.Second

// askModel спрашивает модель, если она подключена. В теневом режиме её находки
// только пишутся в журнал
func (l *Loop) askModel(subject string, vector features.Vector) []Verdict {
	if l.model == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), modelTimeout)
	defer cancel()
	found, err := l.model.ScoreVector(ctx, vector)
	if err != nil {
		if l.log != nil {
			l.log("domainrules: model %s failed: %v", l.model.Name(), err)
		}
		return nil
	}
	if l.modelShadow {
		for _, f := range found {
			if l.log != nil {
				l.log("domainrules: shadow %s would accuse %s of %s (%s)",
					l.model.Name(), subject, f.Kind, f.Why)
			}
		}
		return nil
	}
	out := make([]Verdict, 0, len(found))
	for _, f := range found {
		out = append(out, Verdict{SubjectID: subject, Kind: f.Kind, Count: f.Count, Why: f.Why})
	}
	return out
}

// modelTimeout - сколько ждём модель. Разбор идёт по расписанию, и висеть на
// внешнем сервисе весь круг незачем
const modelTimeout = 30 * time.Second

// featureSightings переводит наблюдения в форму, которую считает слой признаков
func featureSightings(in []Sighting) []features.Sighting {
	out := make([]features.Sighting, 0, len(in))
	for _, s := range in {
		out = append(out, features.Sighting{
			Domain: s.Domain, Port: s.Port, Count: s.Count,
			UpBytes: s.UpBytes, DownBytes: s.DownBytes,
			LongLived: s.LongLived, At: s.LastSeen,
		})
	}
	return out
}
