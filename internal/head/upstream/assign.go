package upstream

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Купленную подписку нельзя вываливать всем разом: у любого оплаченного тарифа
// есть свой потолок, и если раздать её толпе, продавец увидит толпу. Поэтому
// источник закрепляется за ограниченным числом людей и держится за ними, а не
// перескакивает при каждом обновлении - иначе у человека список серверов
// пляшет от захода к заходу

// holdFor - на сколько источник закрепляется за человеком
const holdFor = 24 * time.Hour

// holder - кому и до каких пор отдан источник
type holder struct {
	SubjectID string
	Until     time.Time
}

// Trust решает, можно ли этому человеку давать купленный сервер.
//
// Гейт обязателен, и это главная слабость всей затеи: за чужим сервером нашего
// агента нет, а значит нет ни доменов, ни отпечатков, ни сверки объёма - Oracle
// там слеп нахуй. Мошенник, посаженный на купленную подписку, невидим, а бан за
// его художества прилетит на НАШ аккаунт у продавца. Поэтому туда пускаем
// только тех, к кому доверие уже есть
type Trust interface {
	// TrustedForUpstream - можно ли пускать за пределы своего флота
	TrustedForUpstream(subjectID string) bool
}

// Assigner раздаёт источники людям
type Assigner struct {
	mu    sync.Mutex
	pool  *Pool
	trust Trust
	held  map[string][]holder
	now   func() time.Time
	holdT time.Duration
}

func NewAssigner(pool *Pool) *Assigner {
	return &Assigner{pool: pool, held: map[string][]holder{}, now: time.Now, holdT: holdFor}
}

// SetTrust вешает гейт по доверию
func (a *Assigner) SetTrust(trust Trust) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trust = trust
}

// For отдаёт ссылки, закреплённые за человеком.
//
// Раздача устойчива: пока источник не переполнен и закрепление не истекло,
// человек видит те же серверы, что и вчера
func (a *Assigner) For(subjectID string) []Link {
	if subjectID == "" {
		return nil
	}
	if !a.pool.Enabled() {
		return nil
	}
	sources := a.pool.List()
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.trust != nil && !a.trust.TrustedForUpstream(subjectID) {
		// Не отказ в доступе: свои ноды у человека остаются, слепой зоны ему
		// просто не дают
		return nil
	}
	now := a.now()

	var out []Link
	for _, source := range sources {
		if !source.Enabled || len(source.Links) == 0 {
			continue
		}
		if !a.holdLocked(source, subjectID, now) {
			continue
		}
		// Ссылку внутри источника закрепляем за человеком отпечатком: у
		// подписки их обычно несколько, и каждому нужна своя, а не первая
		at := pick(subjectID, source.ID, len(source.Links))
		name := nameFor(source, at)
		out = append(out, Link{
			SourceID: source.ID,
			Vendor:   source.Vendor,
			Name:     name,
			Raw:      Rename(source.Links[at], name),
		})
	}
	return out
}

// Link - одна ссылка купленного сервера, как её отдают человеку
type Link struct {
	SourceID string
	Vendor   string
	Name     string
	Raw      string
}

// nameFor приклеивает нашего вендора к тому, как сервер назвал сам продавец.
//
// Их подпись оставляем: в ней страна, флаг и пометка тарифа, и человеку она
// говорит больше, чем наш порядковый номер. Наш вендор идёт первым, чтобы в
// общем списке было видно, чей это сервер.
//
// Решётки в имени быть НЕ ДОЛЖНО: имя едет во фрагменте ссылки, а фрагмент все
// читают от последней решётки. С "Durev #5" человек увидел бы сервер по имени
// "5" и охуел бы, откуда тот взялся
func nameFor(source Source, at int) string {
	vendor := strings.TrimSpace(source.Vendor)
	if vendor == "" {
		vendor = source.ID
	}
	name := vendor
	if theirs := labelOf(source.Links[at]); theirs != "" {
		name = vendor + " " + theirs
	} else if len(source.Links) > 1 {
		name = fmt.Sprintf("%s %d", vendor, at+1)
	}
	return strings.TrimSpace(strings.ReplaceAll(name, "#", ""))
}

// labelOf достаёт подпись, которую дал сам продавец
func labelOf(raw string) string {
	at := strings.LastIndex(raw, "#")
	if at < 0 || at+1 >= len(raw) {
		return ""
	}
	label := raw[at+1:]
	if decoded, err := url.QueryUnescape(label); err == nil {
		label = decoded
	}
	return strings.TrimSpace(label)
}

// holdLocked решает, достаётся ли источник этому человеку. Держит замок
func (a *Assigner) holdLocked(source Source, subjectID string, now time.Time) bool {
	kept := a.held[source.ID][:0]
	var mine bool
	for _, h := range a.held[source.ID] {
		if !h.Until.After(now) {
			continue
		}
		if h.SubjectID == subjectID {
			mine = true
			h.Until = now.Add(a.holdT)
		}
		kept = append(kept, h)
	}
	a.held[source.ID] = kept
	if mine {
		return true
	}
	if source.MaxClients > 0 && len(kept) >= source.MaxClients {
		// Потолок выбран: этому человеку источник не достаётся, и это не
		// поломка - у него есть свои ноды федерации
		return false
	}
	a.held[source.ID] = append(kept, holder{SubjectID: subjectID, Until: now.Add(a.holdT)})
	return true
}

// pick выбирает ссылку внутри источника устойчиво к перезапуску: случайный
// выбор менял бы человеку сервер на каждом обновлении подписки
func pick(subjectID, sourceID string, n int) int {
	if n <= 1 {
		return 0
	}
	sum := sha512.Sum512_256([]byte(subjectID + "|" + sourceID))
	return int(binary.BigEndian.Uint32(sum[:4]) % uint32(n))
}

// Rename подставляет в ссылку наше имя сервера.
//
// Продавец пишет туда своё, и в списке у человека это выглядит как посторонний
// сервер неизвестно откуда
func Rename(raw, name string) string {
	if name == "" {
		return raw
	}
	// Имя кодируем: клиенты выдирают ссылки из тела подписки по пробелу, и
	// живое имя вроде "Durev Spain 2" обрезалось бы до первого слова, а половина
	// параметров уезжала бы в мусор
	escaped := escapeFragment(name)
	if at := strings.LastIndex(raw, "#"); at >= 0 {
		return raw[:at+1] + escaped
	}
	return raw + "#" + escaped
}

// escapeFragment прячет пробелы и прочее, что рвёт строку. Плюс тут значит
// именно плюс, а не пробел, поэтому QueryEscape не годится
func escapeFragment(name string) string {
	escaped := url.PathEscape(name)
	return strings.ReplaceAll(escaped, "+", "%2B")
}

// MinConfidence - ниже этого за пределы своего флота не пускаем.
//
// Планка нарочно почти под потолок: на купленном сервере нашего агента нет, и
// Oracle там не видит ни доменов, ни отпечатков, ни сверки объёма. Значит
// человек должен быть чист ДО того, как уйдёт в слепую зону, а не выясняться
// потом по жалобе продавца
const MinConfidence = 95

// Verdicts - откуда берётся доверие. Узкий интерфейс нарочно: раздаче
// купленного незачем знать про Oracle целиком
type Verdicts interface {
	// Confidence - текущее доверие и полный ли у человека доступ
	Confidence(subjectID string) (score int, full bool)
}

// TrustAbove пускает наружу только тех, кто чист и в полной полосе
func TrustAbove(min int, verdicts Verdicts) Trust {
	return &confidenceGate{min: min, verdicts: verdicts}
}

type confidenceGate struct {
	min      int
	verdicts Verdicts
}

func (c *confidenceGate) TrustedForUpstream(subjectID string) bool {
	if c.verdicts == nil {
		return false
	}
	score, full := c.verdicts.Confidence(subjectID)
	return full && score >= c.min
}
