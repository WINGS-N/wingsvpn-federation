// Package oracle scores how much a client is trusted and decides what happens
// to them.
//
// Rules first, but the shape is built for what comes after: a Scorer can be
// swapped for a learned model, signals are kept as features rather than folded
// away, and every verdict records who produced it
package oracle

import (
	"fmt"
	"sort"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Confidence runs 0 to 100 and starts at the top: a new client has done nothing
// wrong, and starting them mid-scale would throttle every free user on arrival.
// Signals subtract from here
const (
	StartingConfidence = 100
	MaxConfidence      = 100
)

// Band is what the head does with a client
type Band int

const (
	// BandFull gets the normal allocation
	BandFull Band = iota
	// BandReduced still works, on fewer nodes and rate capped. Deliberately not
	// a ban: most suspicion is wrong, and a throttle that annoys a real user is
	// recoverable where a ban is not
	BandReduced
	// BandQuarantine is refused assignment and has existing profiles revoked
	BandQuarantine
)

func (b Band) String() string {
	switch b {
	case BandFull:
		return "full"
	case BandReduced:
		return "reduced"
	default:
		return "quarantine"
	}
}

// Thresholds where the bands meet
const (
	fullThreshold    = 60
	reducedThreshold = 30
)

// BandFor maps a confidence onto what to do
func BandFor(confidence int) Band {
	switch {
	case confidence >= fullThreshold:
		return BandFull
	case confidence >= reducedThreshold:
		return BandReduced
	default:
		return BandQuarantine
	}
}

// Signal is one observation about a client. Kept with its timestamp rather than
// folded straight into a counter: rules do not need the history, but anything
// learned later will, and it cannot be recovered once discarded
type Signal struct {
	ClientID string
	Kind     fedpb.AbuseKind
	Weight   float64
	Count    uint32
	Observed time.Time
	// NodeID is where it was seen, which is what makes a donor faking signals
	// against a client visible later
	NodeID string
}

// Verdict is a scored decision
type Verdict struct {
	ClientID   string
	Confidence int
	Band       Band
	// Scorer names what produced this, so a decision can be attributed after the
	// fact and two scorers can be compared
	Scorer string
	// Contributions says which classes cost the client points, so an admin can
	// answer why somebody was cut off
	Contributions map[fedpb.AbuseKind]float64
	// Credit - сколько очков вернул донат. Отдельным полем, чтобы человек видел
	// не только за что его наказали, но и что его занос учтён
	Credit float64
	At     time.Time
}

// Scorer turns a client's signals into a verdict. The rules implementation is
// the only one today; a learned one plugs in beside it
type Scorer interface {
	Name() string
	Score(clientID string, signals []Signal, now time.Time) Verdict
}

// RetainWindow - за какой срок судья поднимает историю после запуска
const RetainWindow = 30 * 24 * time.Hour

// halfLife is how long a signal keeps half its weight. Seven days means a bad
// week stops following somebody around for a month
const halfLife = 7 * 24 * time.Hour

// Weights are tunable without a deploy, which is what lets a rules engine
// survive contact with reality
type Weights map[fedpb.AbuseKind]float64

// DefaultWeights is a starting point, not a truth
func DefaultWeights() Weights {
	return Weights{
		fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT:  14,
		fedpb.AbuseKind_ABUSE_KIND_PORT_SCAN:    20,
		fedpb.AbuseKind_ABUSE_KIND_MAIL_PORT:    18,
		fedpb.AbuseKind_ABUSE_KIND_TORRENT:      8,
		fedpb.AbuseKind_ABUSE_KIND_MALWARE:      25,
		fedpb.AbuseKind_ABUSE_KIND_UPLOAD_HEAVY: 6,
		fedpb.AbuseKind_ABUSE_KIND_ADS:          1,
		// Дороже фанаута: одновременная работа из разных концов страны почти не
		// бывает случайной, тогда как десяток адресов даёт любой мобильный
		fedpb.AbuseKind_ABUSE_KIND_GEO_SPREAD: 16,
		// Дорого: тело подписки это сырой кадр, руками за ним не ходят, а наше
		// приложение называет устройство всегда. Значит пришёл либо чужой
		// клиент, либо человек с пересланной ссылкой
		fedpb.AbuseKind_ABUSE_KIND_NO_DEVICE_ID: 22,
		// Дорого: расписки это единственная сверка объёма, и клиент, который их
		// не шлёт, ломает её намеренно
		fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS: 20,
		// Умеренно: за вторым VPN человек может сидеть по своим причинам, а вот
		// когда это сходится с другими сигналами, картина складывается
		fedpb.AbuseKind_ABUSE_KIND_ADDRESS_MISMATCH: 12,
		// Дороже фанаута по адресам: адрес у мобильного меняется законно, а
		// набор TLS-стеков держится за устройством, и подделать его клиент не
		// может, не переписав свои приложения
		fedpb.AbuseKind_ABUSE_KIND_CLIENT_SPREAD: 18,
		// Дешевле разброса стеков: ровная полка бывает и у человека, который
		// держит на туннеле что-то постоянное, а вот вместе с остальным она
		// складывается в ферму
		fedpb.AbuseKind_ABUSE_KIND_FLAT_RHYTHM: 15,
	}
}

// RulesScorer is a leaky bucket per class with exponential decay
type RulesScorer struct {
	Weights Weights
}

// NewRulesScorer builds a scorer with the default weights
func NewRulesScorer() *RulesScorer { return &RulesScorer{Weights: DefaultWeights()} }

// Name identifies this scorer in a verdict
func (r *RulesScorer) Name() string { return "rules-v1" }

// Score folds the signals into a confidence
func (r *RulesScorer) Score(clientID string, signals []Signal, now time.Time) Verdict {
	buckets := make(map[fedpb.AbuseKind]float64)
	for _, s := range signals {
		age := now.Sub(s.Observed)
		if age < 0 {
			age = 0
		}
		// Exponential decay by half life, computed without math.Pow so the
		// arithmetic stays obvious
		decay := 1.0
		for remaining := age; remaining >= halfLife; remaining -= halfLife {
			decay /= 2
		}
		weight := s.Weight
		if weight == 0 {
			weight = r.Weights[s.Kind]
		}
		buckets[s.Kind] += weight * magnitude(s.Count) * decay
	}
	penalty := 0.0
	for _, v := range buckets {
		penalty += v
	}
	confidence := StartingConfidence - int(penalty)
	if confidence < 0 {
		confidence = 0
	}
	if confidence > MaxConfidence {
		confidence = MaxConfidence
	}
	return Verdict{
		ClientID:      clientID,
		Confidence:    confidence,
		Band:          BandFor(confidence),
		Scorer:        r.Name(),
		Contributions: buckets,
		At:            now,
	}
}

// magnitude превращает величину сигнала в множитель с насыщением.
//
// Умножать вес на голый count нельзя: у фанаута count это число адресов, у
// гео-разброса сотни километров, и линейное умножение отправляло человека в
// карантин с ОДНОГО срабатывания. Один сигнал обязан лишь двигать доверие, а
// топит пусть повторяемость, у которой своё слагаемое в сумме
func magnitude(count uint32) float64 {
	switch {
	case count <= 1:
		return 1
	case count <= 3:
		return 1.3
	case count <= 8:
		return 1.6
	case count <= 20:
		return 2
	default:
		return 2.5
	}
}

// Judge holds the signal history and applies a scorer
type Judge struct {
	mu      sync.Mutex
	signals map[string][]Signal
	scorer  Scorer
	// shadow runs beside the live scorer and decides nothing. Switching to a
	// learned model blind is how you cut off half your users overnight
	shadow   Scorer
	verdicts map[string]Verdict
	shadows  map[string]Verdict
	now      func() time.Time
	// retain bounds the history. Long enough to train on, short enough that a
	// busy fleet does not grow without limit
	retain time.Duration
	// sink уносит сигналы и вердикты в базу: после выката башки иначе не
	// ответить, за что человека отрезали
	sink Sink
	// credits - заносы в общий котёл. Греют доверие, но с потолком
	credits map[string][]Credit
}

// Sink пишет наблюдения и решения туда, где они переживут выкат
type Sink interface {
	Signal(s Signal) error
	Decision(v Verdict) error
	Load(since time.Time) ([]Signal, error)
}

// SetSink подключает хранилище
func (j *Judge) SetSink(sink Sink) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.sink = sink
}

// Restore поднимает историю сигналов из хранилища
func (j *Judge) Restore(since time.Time) error {
	j.mu.Lock()
	sink := j.sink
	j.mu.Unlock()
	if sink == nil {
		return nil
	}
	stored, err := sink.Load(since)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, s := range stored {
		j.signals[s.ClientID] = append(j.signals[s.ClientID], s)
	}
	return nil
}

// NewJudge builds a judge around a scorer
func NewJudge(scorer Scorer) *Judge {
	return &Judge{
		signals:  make(map[string][]Signal),
		verdicts: make(map[string]Verdict),
		shadows:  make(map[string]Verdict),
		scorer:   scorer,
		now:      time.Now,
		retain:   30 * 24 * time.Hour,
	}
}

// SetNow overrides the clock. Only tests have any business calling it: a judge
// whose clock can be moved from outside is a judge whose decay can be
func (j *Judge) SetNow(now func() time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.now = now
}

// SetShadow installs a scorer that observes without deciding
func (j *Judge) SetShadow(s Scorer) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.shadow = s
}

// Observe records a signal.
//
// Only metered federation profiles ever reach here. An admin's paying client on
// a vanilla app produces no signals and must never be scored
func (j *Judge) Observe(s Signal) {
	if j.sink != nil {
		_ = j.sink.Signal(s)
	}
	if s.Observed.IsZero() {
		s.Observed = j.now()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.signals[s.ClientID] = append(j.signals[s.ClientID], s)
	j.pruneLocked(s.ClientID)
}

func (j *Judge) pruneLocked(clientID string) {
	cutoff := j.now().Add(-j.retain)
	kept := j.signals[clientID][:0]
	for _, s := range j.signals[clientID] {
		if s.Observed.After(cutoff) {
			kept = append(kept, s)
		}
	}
	j.signals[clientID] = kept
}

// Judge scores a client and records the verdict
func (j *Judge) Judge(clientID string) Verdict {
	j.mu.Lock()
	signals := append([]Signal(nil), j.signals[clientID]...)
	shadow := j.shadow
	credits := append([]Credit(nil), j.credits[clientID]...)
	j.mu.Unlock()

	now := j.now()
	verdict := j.scorer.Score(clientID, signals, now)
	// Донат гасит часть штрафов: тот, кто занёс в общий котёл, ведёт себя не как
	// ферма. Но карантинного не греет вообще, иначе выходило бы, что право
	// скамить продаётся, а это ровно то, чего мы не хотим
	if credit := creditValue(credits, now); credit > 0 && verdict.Band != BandQuarantine {
		verdict.Confidence += int(credit)
		if verdict.Confidence > MaxConfidence {
			verdict.Confidence = MaxConfidence
		}
		verdict.Band = BandFor(verdict.Confidence)
		verdict.Credit = credit
	}

	j.mu.Lock()
	previous, seen := j.verdicts[clientID]
	j.verdicts[clientID] = verdict
	if shadow != nil {
		j.shadows[clientID] = shadow.Score(clientID, signals, now)
	}
	sink := j.sink
	j.mu.Unlock()
	// Пишем смену полосы, а не каждый пересчёт: он идёт раз в несколько секунд
	if sink != nil && (!seen || previous.Band != verdict.Band) {
		_ = sink.Decision(verdict)
	}
	return verdict
}

// Shadow returns what the observing scorer would have decided
func (j *Judge) Shadow(clientID string) (Verdict, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	v, ok := j.shadows[clientID]
	return v, ok
}

// Features exports a client's signal history for training. This is the reason
// signals are stored rather than folded away
func (j *Judge) Features(clientID string) []Signal {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := append([]Signal(nil), j.signals[clientID]...)
	sort.Slice(out, func(i, k int) bool { return out[i].Observed.Before(out[k].Observed) })
	return out
}

// Explain renders why a client sits where it does, so an admin can answer the
// question rather than shrug at it
func (v Verdict) Explain() string {
	if len(v.Contributions) == 0 {
		return fmt.Sprintf("%s: %d, nothing held against them", v.Band, v.Confidence)
	}
	type row struct {
		kind fedpb.AbuseKind
		cost float64
	}
	rows := make([]row, 0, len(v.Contributions))
	for k, c := range v.Contributions {
		rows = append(rows, row{k, c})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].cost > rows[j].cost })
	out := fmt.Sprintf("%s: %d (%s)", v.Band, v.Confidence, v.Scorer)
	for _, r := range rows {
		out += fmt.Sprintf(", %s -%.1f", r.kind, r.cost)
	}
	return out
}

// Accused lists every client the judge has anything on. Used by the enforcement
// pass, which has no business re-judging clients nobody reported
func (j *Judge) Accused() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]string, 0, len(j.signals))
	for id, signals := range j.signals {
		if len(signals) > 0 {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Verdicts returns the last decision on each client, for an operator asking who
// is where and why
func (j *Judge) Verdicts() map[string]Verdict {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make(map[string]Verdict, len(j.verdicts))
	for id, v := range j.verdicts {
		out[id] = v
	}
	return out
}

// speedFloor и speedCeiling - границы, между которыми Oracle раздаёт скорость,
// байт в секунду. Потолок не безлимитный намеренно: бесплатный доступ живёт на
// пожертвованных каналах, и один клиент не должен выбирать их целиком
const (
	speedFloorUplink     = 1 << 20
	speedFloorDownlink   = 2 << 20
	speedCeilingUplink   = 25 << 20
	speedCeilingDownlink = 50 << 20
)

// SpeedFor - какая скорость положена при такой оценке, байт в секунду вверх и
// вниз.
//
// Считается от самой оценки, а не от полосы: полоса - это грубые три ступени,
// и на ней клиент с 59 очками получал бы то же, что клиент с 31. Ограничение
// должно быть соразмерно подозрению, а не округлено до ступени.
//
// Ниже порога карантина скорость не считается вовсе: там уже нечего отдавать
func SpeedFor(confidence int) (uplinkBps, downlinkBps uint64) {
	if confidence <= reducedThreshold {
		return speedFloorUplink, speedFloorDownlink
	}
	if confidence >= MaxConfidence {
		return speedCeilingUplink, speedCeilingDownlink
	}
	span := float64(MaxConfidence - reducedThreshold)
	weight := float64(confidence-reducedThreshold) / span
	up := float64(speedFloorUplink) + weight*float64(speedCeilingUplink-speedFloorUplink)
	down := float64(speedFloorDownlink) + weight*float64(speedCeilingDownlink-speedFloorDownlink)
	return uint64(up), uint64(down)
}

// quotaFloor и quotaCeiling - месячный потолок, между которыми объём режется у
// подозрительных. Пол не ноль нахуй: даже под подозрением человеку надо
// оставить столько, чтобы он пользовался связью, а не пялился в счётчик
const (
	quotaFloorBytes   = 20 << 30
	quotaCeilingBytes = 300 << 30
)

// QuotaUnlimited - потолка нет. Ровно то, что получает чистый человек
const QuotaUnlimited = 0

// QuotaFor - сколько байт в месяц положено при такой оценке.
//
// Потолок это НАКАЗАНИЕ, а не ебаный тариф: в полной полосе его нет вовсе.
// Ниже считается от самой оценки, а не от полосы, ровно как скорость - три
// ступени означали бы, что человек с 59 очками и мудак с 31 качают поровну
func QuotaFor(confidence int) uint64 {
	if confidence >= fullThreshold {
		return QuotaUnlimited
	}
	if confidence <= reducedThreshold {
		return quotaFloorBytes
	}
	span := float64(fullThreshold - reducedThreshold)
	weight := float64(confidence-reducedThreshold) / span
	return uint64(float64(quotaFloorBytes) + weight*float64(quotaCeilingBytes-quotaFloorBytes))
}

// FloorSpeed - самый нижний потолок. На него садится тот, кто выбрал месячную
// квоту: связь остаётся, но медленная
func FloorSpeed() (uplinkBps, downlinkBps uint64) {
	return speedFloorUplink, speedFloorDownlink
}

// DevicesFor is how many devices may hold this account's subscription.
//
// Полоса решает и это: у человека телефон, планшет и, может, второй телефон, а
// вот три десятка устройств на одном аккаунте это уже раздача ссылки дальше.
// Подозрительному режем до пары, чистому оставляем запас
func (b Band) DevicesFor() int {
	switch b {
	case BandFull:
		return 5
	case BandReduced:
		return 2
	default:
		return 0
	}
}

// NodesFor is how many nodes a client in this band gets.
//
// Reduced is deliberately not zero: most suspicion is wrong, and a throttle that
// annoys a real user is recoverable where cutting them off is not
func (b Band) NodesFor() int {
	switch b {
	case BandFull:
		return 2
	case BandReduced:
		return 1
	default:
		return 0
	}
}
