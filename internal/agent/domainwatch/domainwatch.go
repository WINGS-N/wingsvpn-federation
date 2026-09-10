// Package domainwatch собирает с ядра, куда ходили профили федерации.
//
// Бесплатный доступ без разбора трафика сжирают фермы и перепродажники, поэтому
// смотреть приходится плотно. Границы при этом жёсткие: на донорской машине не
// оседает нихуя, сырые события не хранятся, наверх уезжает свёрнутый счётчик за
// окно, и трогаются только профили федерации - платящие клиенты донора живут на
// той же ноде и их это не касается вообще
package domainwatch

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	xraypb "wingsnet.org/federation/gen/xraypb"
)

// DefaultWindow - за какой срок счётчики сворачиваются в один отчёт
const DefaultWindow = 60 * time.Second

// longLivedMs - с какой длительности соединение считается долгим. Всё, что
// короче, это обычная возня браузера за картинками
const longLivedMs = 30_000

// maxSamples ограничивает отчёт. Домены - это хвост длиной в интернет, и
// отправлять его целиком означает завалить башку мусором из одного захода
const maxSamples = 512

// Profiles говорит, какие теги ядра принадлежат федерации
type Profiles interface {
	// MeteredProfiles сопоставляет email-тег Xray с идентификатором профиля
	MeteredProfiles() map[string]string
}

type key struct {
	profileID string
	domain    string
	port      uint32
}

// portKey - соединения без домена, сведённые по порту
type portKey struct {
	profileID string
	port      uint32
}

// printKey - профиль и отпечаток его TLS-стека
type printKey struct {
	profileID string
	ja4       string
}

type printCounter struct {
	ja3       string
	count     uint32
	firstSeen int64
	lastSeen  int64
}

type portCounter struct {
	count   uint32
	targets map[string]struct{}
	up      uint64
	down    uint64
}

type counter struct {
	count     uint32
	up        uint64
	down      uint64
	longLived uint32
	firstSeen int64
	lastSeen  int64
}

// Watcher держит подписку на ядро и копит счётчики до отправки
type Watcher struct {
	profiles Profiles
	window   time.Duration

	mu      sync.Mutex
	buckets map[key]*counter
	ports   map[portKey]*portCounter
	prints  map[printKey]*printCounter
	dropped uint64
}

func New(profiles Profiles) *Watcher {
	return &Watcher{
		profiles: profiles, window: DefaultWindow,
		buckets: map[key]*counter{}, ports: map[portKey]*portCounter{},
		prints: map[printKey]*printCounter{},
	}
}

// Run держит стрим, пока жив ctx. Обрыв не беда: ядро без подписчика просто
// перестаёт наблюдать, а мы переподключаемся
func (w *Watcher) Run(ctx context.Context, client xraypb.WingsWatchClient) error {
	stream, err := client.StreamAccess(ctx, &xraypb.StreamAccessRequest{})
	if err != nil {
		return err
	}
	// Без этой строки непонятно, подписались мы или молча висим впустую
	log.Printf("domainwatch: subscribed to the core")
	for {
		event, err := stream.Recv()
		if err != nil {
			return err
		}
		w.Observe(event)
	}
}

// Observe складывает одно событие в счётчики. Чужие профили пролетают мимо
func (w *Watcher) Observe(event *xraypb.AccessEvent) {
	profileID, ok := w.profiles.MeteredProfiles()[event.GetEmail()]
	if !ok {
		return
	}
	w.observeFor(profileID, event)
}

// observeFor складывает событие уже известного профиля. Отдельный вход нужен
// наблюдениям с wg-интерфейса: там профиль известен сразу, по адресу пира, а
// учётки ядра нет вовсе
func (w *Watcher) observeFor(profileID string, event *xraypb.AccessEvent) {
	domain := normalizeDomain(event.GetTargetDomain())
	at := event.GetAtUnixNano() / int64(time.Second)

	w.mu.Lock()
	defer w.mu.Unlock()

	w.observePrint(profileID, event, at)

	// Соединение без домена считается по порту: голый адрес это торрент, чужой
	// прокси или скан, и в доменах такое не видно вообще
	if domain == "" {
		w.observePort(profileID, event)
		return
	}

	k := key{profileID: profileID, domain: domain, port: event.GetTargetPort()}
	entry, exists := w.buckets[k]
	if !exists {
		if len(w.buckets) >= maxSamples {
			w.dropped++
			return
		}
		entry = &counter{firstSeen: at}
		w.buckets[k] = entry
	}
	entry.count++
	entry.up += event.GetUpBytes()
	entry.down += event.GetDownBytes()
	if event.GetDurationMs() >= longLivedMs {
		entry.longLived++
	}
	if at < entry.firstSeen || entry.firstSeen == 0 {
		entry.firstSeen = at
	}
	if at > entry.lastSeen {
		entry.lastSeen = at
	}
}

// observePrint копит отпечатки TLS. Вызывается под замком
func (w *Watcher) observePrint(profileID string, event *xraypb.AccessEvent, at int64) {
	ja4 := event.GetTlsJa4()
	if ja4 == "" {
		return
	}
	k := printKey{profileID: profileID, ja4: ja4}
	entry, ok := w.prints[k]
	if !ok {
		// Отпечатков у живого человека единицы, так что упереться в потолок
		// выйдет только на расшаренном профиле, а это ровно то, что мы и ловим
		if len(w.prints) >= maxSamples {
			w.dropped++
			return
		}
		entry = &printCounter{ja3: event.GetTlsJa3(), firstSeen: at}
		w.prints[k] = entry
	}
	entry.count++
	if at < entry.firstSeen || entry.firstSeen == 0 {
		entry.firstSeen = at
	}
	if at > entry.lastSeen {
		entry.lastSeen = at
	}
}

// observePort копит соединения без домена. Вызывается под замком
func (w *Watcher) observePort(profileID string, event *xraypb.AccessEvent) {
	k := portKey{profileID: profileID, port: event.GetTargetPort()}
	entry, ok := w.ports[k]
	if !ok {
		if len(w.ports) >= maxSamples {
			w.dropped++
			return
		}
		entry = &portCounter{targets: map[string]struct{}{}}
		w.ports[k] = entry
	}
	entry.count++
	entry.up += event.GetUpBytes()
	entry.down += event.GetDownBytes()
	// Адреса нужны только чтобы посчитать их число, сами они наверх не едут
	if addr := event.GetTargetIp(); addr != "" && len(entry.targets) < 4096 {
		entry.targets[addr] = struct{}{}
	}
}

// AddDropped учитывает то, что ядро выкинуло само
func (w *Watcher) AddDropped(n uint64) {
	w.mu.Lock()
	w.dropped += n
	w.mu.Unlock()
}

// Drain отдаёт накопленное и забывает. Забывает намертво, это и есть обещание
// про то, что на ноде ничего не остаётся
func (w *Watcher) Drain() *fedpb.DomainBatch {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buckets) == 0 && len(w.ports) == 0 && len(w.prints) == 0 && w.dropped == 0 {
		return nil
	}
	batch := &fedpb.DomainBatch{
		WindowSeconds: uint32(w.window.Seconds()),
		Dropped:       w.dropped,
		Samples:       make([]*fedpb.DomainSample, 0, len(w.buckets)),
	}
	for k, entry := range w.buckets {
		batch.Samples = append(batch.Samples, &fedpb.DomainSample{
			ProfileId:     k.profileID,
			Domain:        k.domain,
			Count:         entry.count,
			UpBytes:       entry.up,
			DownBytes:     entry.down,
			LongLived:     entry.longLived,
			FirstSeenUnix: entry.firstSeen,
			LastSeenUnix:  entry.lastSeen,
			Port:          k.port,
		})
	}
	for k, entry := range w.ports {
		batch.Ports = append(batch.Ports, &fedpb.PortSample{
			ProfileId:       k.profileID,
			Port:            k.port,
			Count:           entry.count,
			DistinctTargets: uint32(len(entry.targets)),
			UpBytes:         entry.up,
			DownBytes:       entry.down,
		})
	}
	for k, entry := range w.prints {
		batch.Prints = append(batch.Prints, &fedpb.ClientPrint{
			ProfileId:     k.profileID,
			Ja4:           k.ja4,
			Ja3:           entry.ja3,
			Count:         entry.count,
			FirstSeenUnix: entry.firstSeen,
			LastSeenUnix:  entry.lastSeen,
		})
	}
	w.buckets = map[key]*counter{}
	w.ports = map[portKey]*portCounter{}
	w.prints = map[printKey]*printCounter{}
	w.dropped = 0
	return batch
}

// normalizeDomain приводит имя к одному виду. Ядро может отдать его с точкой на
// конце или в разном регистре, и без этого один домен размажется по трём ключам
func normalizeDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" || strings.ContainsAny(domain, " /\\") {
		return ""
	}
	return domain
}
