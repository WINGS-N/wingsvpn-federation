// Package domainfeed тянет чужие списки плохих доменов.
//
// Руками поддерживаемый набор слов на этой войне не работает нихуя: кардинг-
// лавка и фишинг живут неделю, домен сгорает вместе с площадкой, и пока мы
// допишем в список одно имя, этой хуйни наплодят сотню. Списки ведут люди,
// которые ловят её целыми днями, и пиздить их - единственный способ поспевать.
//
// Фид НЕ заменяет свои правила, а ложится рядом: чужой список знает про уже
// спалившиеся домены, а разбор по форме поведения ловит то, чего ни в одном
// списке ещё нет
package domainfeed

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Feed - один внешний список
type Feed struct {
	ID  string
	URL string
	// Kind - чем считать попадание в этот список
	Kind fedpb.AbuseKind
}

// DefaultFeeds - с чем начинаем. Оба списка публичные и бесплатные, и оба ведут
// те, кто эту мразь ловит профессионально
func DefaultFeeds() []Feed {
	return []Feed{
		{
			ID:   "urlhaus",
			URL:  "https://urlhaus.abuse.ch/downloads/hostfile/",
			Kind: fedpb.AbuseKind_ABUSE_KIND_MALWARE,
		},
		{
			ID:   "phishing-army",
			URL:  "https://phishing.army/download/phishing_army_blocklist_extended.txt",
			Kind: fedpb.AbuseKind_ABUSE_KIND_MALWARE,
		},
	}
}

// Every - как часто перечитываем списки. Двенадцати часов за глаза: домен из
// свежей волны доедет к нам в тот же день, а долбиться в чужой сервер чаще -
// это охуеть какая наглость и прямой путь словить бан по адресу
const Every = 12 * time.Hour

// fetchTimeout - списки крупные, но не бесконечные
const fetchTimeout = 2 * time.Minute

// maxBody - потолок на тело. Любому из списков хватает с запасом, а без потолка
// один кривой ответ сожрёт башке всю память нахуй
const maxBody = 32 << 20

// maxDomains - потолок на число имён из одного списка. Защита от того же
const maxDomains = 400000

// Store держит последнюю удачную загрузку: источник может и полежать, а башка
// обязана вставать с тем, что знала вчера, а не с пустотой
type Store interface {
	Load(feedID string) (domains []string, fetchedAt time.Time, err error)
	Save(feedID string, domains []string, fetchedAt time.Time) error
}

// Pool держит списки и отвечает, попадал ли домен хоть в один
type Pool struct {
	mu sync.RWMutex
	// domains - имя в класс. Один общий набор на все фиды: при обвинении похуй,
	// кто именно спалил домен
	domains map[string]fedpb.AbuseKind
	feeds   []Feed
	store   Store
	client  *http.Client
	log     func(string, ...any)
	now     func() time.Time
}

func NewPool(store Store, log func(string, ...any)) *Pool {
	return &Pool{
		domains: map[string]fedpb.AbuseKind{},
		feeds:   DefaultFeeds(),
		store:   store,
		client:  &http.Client{Timeout: fetchTimeout},
		log:     log,
		now:     time.Now,
	}
}

// SetFeeds подменяет набор источников. Нужно тестам и владельцу, если он
// заведёт свои
func (p *Pool) SetFeeds(feeds []Feed) {
	p.mu.Lock()
	p.feeds = feeds
	p.mu.Unlock()
}

// SetHTTP подменяет клиента, чтобы тесты не лезли в живые списки
func (p *Pool) SetHTTP(client *http.Client) { p.client = client }

// Kind говорит, в каком списке домен засветился. Проверяется и сам домен, и его
// родители: списки ведут по домену, а человек приходит на его поддомен
func (p *Pool) Kind(domain string) (fedpb.AbuseKind, bool) {
	name := strings.ToLower(strings.TrimSpace(domain))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return fedpb.AbuseKind_ABUSE_KIND_UNSPECIFIED, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.domains) == 0 {
		return fedpb.AbuseKind_ABUSE_KIND_UNSPECIFIED, false
	}
	for {
		if kind, ok := p.domains[name]; ok {
			return kind, true
		}
		idx := strings.Index(name, ".")
		if idx < 0 {
			break
		}
		name = name[idx+1:]
		// До самой зоны не поднимаемся: "com" в списке означал бы обвинение
		// половине ебаного интернета
		if !strings.Contains(name, ".") {
			break
		}
	}
	return fedpb.AbuseKind_ABUSE_KIND_UNSPECIFIED, false
}

// Size - сколько имён сейчас в наборе
func (p *Pool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.domains)
}

// Restore поднимает списки из хранилища. Зовётся на старте: до первой удачной
// загрузки башка судит по вчерашнему набору, а не по пустоте
func (p *Pool) Restore() {
	if p.store == nil {
		return
	}
	p.mu.RLock()
	feeds := append([]Feed(nil), p.feeds...)
	p.mu.RUnlock()
	for _, feed := range feeds {
		domains, _, err := p.store.Load(feed.ID)
		if err != nil || len(domains) == 0 {
			continue
		}
		p.apply(feed, domains)
		if p.log != nil {
			p.log("domainfeed: %s loaded from the database, %d names", feed.ID, len(domains))
		}
	}
}

// Run обновляет списки по расписанию
func (p *Pool) Run(ctx context.Context) {
	p.Once(ctx)
	ticker := time.NewTicker(Every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Once(ctx)
		}
	}
}

// Once перечитывает все списки один раз
func (p *Pool) Once(ctx context.Context) {
	p.mu.RLock()
	feeds := append([]Feed(nil), p.feeds...)
	p.mu.RUnlock()
	for _, feed := range feeds {
		domains, err := p.fetch(ctx, feed)
		if err != nil {
			// Источник лёг - это не повод забывать всё, что уже знаем нахуй:
			// старый набор остаётся в силе
			if p.log != nil {
				p.log("domainfeed: %s is unreadable: %v", feed.ID, err)
			}
			continue
		}
		p.apply(feed, domains)
		if p.store != nil {
			if err := p.store.Save(feed.ID, domains, p.now()); err != nil && p.log != nil {
				p.log("domainfeed: %s was not stored: %v", feed.ID, err)
			}
		}
		if p.log != nil {
			p.log("domainfeed: %s updated, %d names", feed.ID, len(domains))
		}
	}
}

// apply вкладывает имена одного фида в общий набор
func (p *Pool) apply(feed Feed, domains []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, domain := range domains {
		p.domains[domain] = feed.Kind
	}
}

func (p *Pool) fetch(ctx context.Context, feed Feed) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wingsv-fed")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("answered %d", resp.StatusCode)
	}
	return Parse(io.LimitReader(resp.Body, maxBody))
}

// Parse разбирает тело списка.
//
// Форматов у этих списков ровно три, и все три встречаются: hosts (адрес и имя
// через пробел), голое имя в строке и целый URL. Жуём все, потому что требовать
// от чужого проекта единый вид - это ждать у моря погоды до посинения
func Parse(body io.Reader) ([]string, error) {
	seen := make(map[string]struct{}, 1024)
	out := make([]string, 0, 1024)
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		name := domainOf(line)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
		if len(out) >= maxDomains {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// domainOf вытаскивает имя из строки любого из трёх видов
func domainOf(line string) string {
	// hosts: адрес, пробел, имя. Иногда в конце ещё комментарий
	if fields := strings.Fields(line); len(fields) > 1 {
		if isAddress(fields[0]) {
			line = fields[1]
		} else {
			line = fields[0]
		}
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if strings.Contains(line, "://") {
		parsed, err := url.Parse(line)
		if err != nil {
			return ""
		}
		line = parsed.Hostname()
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(line), "."))
	if name == "" || !strings.Contains(name, ".") {
		return ""
	}
	// Заглушки самого hosts-файла именами не являются
	if name == "localhost" || name == "localhost.localdomain" || name == "broadcasthost" {
		return ""
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return ""
		}
	}
	return name
}

func isAddress(field string) bool {
	return field == "0.0.0.0" || field == "127.0.0.1" || field == "::1" || field == "::"
}
