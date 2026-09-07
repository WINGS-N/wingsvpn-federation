// Package upstream раздаёт профили, купленные на стороне.
//
// Кроме пожертвованных нод у площадки бывают оплаченные подписки: их заводит
// владелец, башка тянет тело по ссылке, разбирает и раздаёт людям наравне со
// своими серверами. Для человека это ещё один сервер в списке, для нас - чужая
// мощность, за которую донорам ничего не начисляется: она куплена, а не отдана.
//
// Держится отдельным пакетом, потому что учёт у неё другой: своего счётчика на
// той стороне нет, самоотчёту верить неоткуда, и в выплаты это не идёт вообще
package upstream

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// refreshEvery - как часто перечитываем тело. Продавец меняет адреса и ключи
// молча, и подписка, прочитанная один раз при старте, протухает без единого
// сообщения об ошибке
const refreshEvery = 30 * time.Minute

// fetchTimeout - дольше ждать нечего, подписка это несколько килобайт
const fetchTimeout = 20 * time.Second

// maxBody ограничивает тело: отдать нам гигабайт вместо подписки может кто
// угодно, а разбирать его потом нам
const maxBody = 1 << 20

var (
	// ErrEmpty - в теле не нашлось ни одной ссылки
	ErrEmpty = errors.New("upstream: subscription carries no links")
	// ErrNoSource - такого источника нет
	ErrNoSource = errors.New("upstream: no such source")
)

// Source - одна купленная подписка
type Source struct {
	ID string
	// Vendor - чьё это добро. Пишет владелец площадки при заведении источника,
	// и именно оно уходит в имя сервера у человека: он должен понимать, чем
	// пользуется, а не гадать над безымянной строкой в списке
	Vendor string
	URL    string
	// DeviceID - чем башка представляется, когда идёт за телом. Один и тот же
	// на все запросы: продавец считает устройства по этому полю, и дёргать его
	// на каждого нашего человека значит выжечь лимит за минуту
	DeviceID string
	// MaxClients - скольким людям эту подписку можно раздать одновременно.
	// Ноль означает без потолка, но ставить так не стоит: у купленного тарифа
	// потолок есть всегда, просто мы его не знаем
	MaxClients int
	Enabled    bool

	// Links - что удалось прочитать в последний раз, FetchedAt - когда
	Links     []string
	FetchedAt time.Time
	LastError string
}

// Relay - запасной путь наружу. Башка сидит в одном месте и светится куда
// сильнее любой ноды, так что её адрес прикроют первым; ноды при этом раскиданы
// по разным сетям, и через них видно то, что башке уже нихуя не видно
type Relay interface {
	FetchVia(ctx context.Context, url string, headers map[string]string, maxBytes uint32) ([]byte, error)
}

// Store хранит источники между выкатами
type Store interface {
	Load() ([]Source, error)
	Save(sources []Source) error
	// LoadEnabled и SaveEnabled держат общий рубильник в базе: решение владельца
	// обязано пережить выкат башки, иначе оно нихуя не стоит
	LoadEnabled() (bool, error)
	SaveEnabled(on bool) error
}

// Pool держит источники и их тела
type Pool struct {
	mu sync.Mutex
	// enabled - общий рубильник, и он выключен, пока владелец не включит сам.
	// За чужим сервером Oracle слеп, так что раздача купленного это осознанное
	// решение человека, а не то, что включается само по факту наличия кода
	enabled bool
	sources map[string]*Source
	store   Store
	relay   Relay
	client  *http.Client
	now     func() time.Time
	log     func(string, ...any)
}

func NewPool(store Store, log func(string, ...any)) *Pool {
	return &Pool{
		sources: map[string]*Source{},
		store:   store,
		client:  &http.Client{Timeout: fetchTimeout},
		now:     time.Now,
		log:     log,
	}
}

// Enable включает или гасит раздачу купленного целиком
func (p *Pool) Enable(on bool) {
	p.mu.Lock()
	p.enabled = on
	store := p.store
	p.mu.Unlock()
	if store == nil {
		return
	}
	if err := store.SaveEnabled(on); err != nil && p.log != nil {
		p.log("upstream: the switch was not stored: %v", err)
	}
}

// Enabled - работает ли раздача вообще
func (p *Pool) Enabled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled
}

// SetRelay включает запасной путь через ноды
func (p *Pool) SetRelay(relay Relay) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.relay = relay
}

// Load поднимает источники из хранилища
func (p *Pool) Load() error {
	if p.store == nil {
		return nil
	}
	sources, err := p.store.Load()
	if err != nil {
		return err
	}
	on, err := p.store.LoadEnabled()
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = on
	for i := range sources {
		source := sources[i]
		p.sources[source.ID] = &source
	}
	return nil
}

// Put заводит или правит источник
func (p *Pool) Put(source Source) error {
	if strings.TrimSpace(source.ID) == "" || strings.TrimSpace(source.URL) == "" {
		return errors.New("upstream: source needs an id and a url")
	}
	p.mu.Lock()
	existing, ok := p.sources[source.ID]
	if ok {
		// Тело и время последнего чтения не трогаем: правка названия не повод
		// оставить людей без ссылок до следующего обхода
		source.Links, source.FetchedAt, source.LastError = existing.Links, existing.FetchedAt, existing.LastError
	}
	p.sources[source.ID] = &source
	p.mu.Unlock()
	return p.persist()
}

// Remove убирает источник
func (p *Pool) Remove(id string) error {
	p.mu.Lock()
	if _, ok := p.sources[id]; !ok {
		p.mu.Unlock()
		return ErrNoSource
	}
	delete(p.sources, id)
	p.mu.Unlock()
	return p.persist()
}

// List отдаёт источники как есть
func (p *Pool) List() []Source {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Source, 0, len(p.sources))
	for _, source := range p.sources {
		out = append(out, *source)
	}
	return out
}

func (p *Pool) persist() error {
	if p.store == nil {
		return nil
	}
	return p.store.Save(p.List())
}

// Refresh перечитывает все включённые источники
func (p *Pool) Refresh(ctx context.Context) {
	if !p.Enabled() {
		// Рубильник выключен - к продавцу не ходим вовсе: лишний запрос это
		// лишний след с нашего адреса
		return
	}
	for _, source := range p.List() {
		if !source.Enabled {
			continue
		}
		links, err := p.fetch(ctx, source)
		p.mu.Lock()
		stored, ok := p.sources[source.ID]
		if ok {
			stored.FetchedAt = p.now()
			if err != nil {
				// Прошлое тело оставляем: продавец мог моргнуть, а выкидывать
				// из-за этого людей с рабочих ссылок незачем
				stored.LastError = err.Error()
			} else {
				stored.Links, stored.LastError = links, ""
			}
		}
		p.mu.Unlock()
		if err != nil && p.log != nil {
			p.log("upstream: %s unreadable: %v", source.ID, err)
		}
	}
	_ = p.persist()
}

// Run перечитывает по расписанию
func (p *Pool) Run(ctx context.Context) {
	p.Refresh(ctx)
	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Refresh(ctx)
		}
	}
}

// fetch тянет тело и разбирает его. Не вышло своим ходом - идём через ноды
func (p *Pool) fetch(ctx context.Context, source Source) ([]string, error) {
	links, err := p.fetchDirect(ctx, source)
	if err == nil {
		return links, nil
	}
	p.mu.Lock()
	relay := p.relay
	p.mu.Unlock()
	if relay == nil {
		return nil, err
	}
	if p.log != nil {
		p.log("upstream: %s unreachable from the head (%v), going through a node", source.ID, err)
	}
	body, relayErr := relay.FetchVia(ctx, source.URL, headersOf(source), maxBody)
	if relayErr != nil {
		// Отдаём ПЕРВУЮ ошибку: она про то, что случилось у нас, и чинить надо
		// именно её, а не то, что заодно не сложилось у ноды
		return nil, err
	}
	links = ParseLinks(body)
	if len(links) == 0 {
		return nil, ErrEmpty
	}
	return links, nil
}

// headersOf - чем представляемся продавцу. Одинаково и со своего адреса, и с
// ноды: меняющееся устройство на той стороне выглядит как новая железка
func headersOf(source Source) map[string]string {
	out := map[string]string{"User-Agent": "WINGS V"}
	if source.DeviceID != "" {
		out["x-hwid"] = source.DeviceID
	}
	return out
}

// fetchDirect ходит своим адресом
func (p *Pool) fetchDirect(ctx context.Context, source Source) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, err
	}
	// Представляемся ровно так же, как в прошлый раз: продавец считает
	// устройства по этому заголовку, и прыгающий идентификатор выглядит как
	// толпа новых железок
	for key, value := range headersOf(source) {
		req.Header.Set(key, value)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream: answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	links := ParseLinks(body)
	if len(links) == 0 {
		return nil, ErrEmpty
	}
	return links, nil
}

// ParseLinks достаёт ссылки из тела подписки.
//
// Единого стандарта нет и не будет: кто-то отдаёт голый список, кто-то base64,
// кто-то JSON - и внутри JSON ссылки лежат где попало, то массивом, то полем
// links, то внутри конфига целиком. Спорить с чужим форматом бессмысленно,
// поэтому жрём всё подряд и выгребаем то, что похоже на ссылку
func ParseLinks(body []byte) []string {
	// Продавцы отдают gzip даже там, где его не просили, и заголовок
	// Content-Encoding при этом не ставят - клиент такое молча не распакует и
	// увидит мусор вместо подписки. Ловим по сигнатуре, а не по заголовку
	body = gunzipIfNeeded(body)
	if links := linksInJSON(body); len(links) > 0 {
		return links
	}
	// Ссылок в теле может не быть вовсе: часть продавцов отдаёт готовые конфиги
	// ядра, и ссылку из них надо собрать самому
	if links := linksFromConfigs(body); len(links) > 0 {
		return links
	}
	if links := linesOf(body); len(links) > 0 {
		return links
	}
	decoded, err := decodeBase64(strings.TrimSpace(string(body)))
	if err != nil {
		return nil
	}
	// Под base64 тоже прячут и JSON, и целые конфиги, а не только список
	if links := linksInJSON(decoded); len(links) > 0 {
		return links
	}
	if links := linksFromConfigs(decoded); len(links) > 0 {
		return links
	}
	return linesOf(decoded)
}

// gunzipIfNeeded распаковывает тело, если оно сжато
func gunzipIfNeeded(body []byte) []byte {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return body
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer func() { _ = reader.Close() }()
	// Потолок тот же, что на само тело: распакованный гигабайт нам ни к чему
	out, err := io.ReadAll(io.LimitReader(reader, maxBody*20))
	if err != nil || len(out) == 0 {
		return body
	}
	return out
}

// linksInJSON обходит любой JSON и собирает всё, что выглядит ссылкой клиента.
//
// Обход рекурсивный нарочно: подписку заворачивают то в массив строк, то в
// объект с полем links, то в целый конфиг с outbounds, и угадывать чужую схему
// значит ломаться на каждом втором продавце
func linksInJSON(body []byte) []string {
	var tree any
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil
	}
	var out []string
	var walk func(node any)
	walk = func(node any) {
		switch value := node.(type) {
		case string:
			if line := strings.TrimSpace(value); isClientLink(line) {
				out = append(out, line)
			}
		case []any:
			for _, item := range value {
				walk(item)
			}
		case map[string]any:
			// Ключи обходим по порядку: иначе набор ссылок скачет от чтения к
			// чтению, а за ним скачет и список серверов у человека
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				walk(value[key])
			}
		}
	}
	walk(tree)
	return out
}

// linesOf выбирает строки, похожие на ссылки клиента
func linesOf(body []byte) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 0, 64*1024), maxBody)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isClientLink(line) {
			out = append(out, line)
		}
	}
	return out
}

// isClientLink - схемы, которые понимает наше приложение. Остальное пропускаем
// молча: в чужом теле попадается что угодно
func isClientLink(line string) bool {
	for _, scheme := range []string{"vless://", "vmess://", "trojan://", "ss://"} {
		if strings.HasPrefix(line, scheme) {
			return true
		}
	}
	return false
}

func decodeBase64(value string) ([]byte, error) {
	// Тело кодируют и обычным алфавитом, и url-safe, и без выравнивания
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("upstream: body is neither a list nor base64")
}
