package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// countryTimeout - сколько ждём один внешний источник. Определение страны не
// должно задерживать вступление ноды
const countryTimeout = 6 * time.Second

// countryTTL - как долго держится определённая страна. Сервер не переезжает
// между странами каждый час, а лишние запросы наружу светят его адрес
const countryTTL = 12 * time.Hour

// externalSources - публичные справочники, отвечающие кодом страны по адресу.
// Их несколько, потому что каждый ошибается по-своему, особенно на хостингах:
// решает совпадение, а не первый ответивший
var externalSources = []struct {
	name string
	url  string
	pick func([]byte) string
}{
	{"ip-api", "http://ip-api.com/json/%s?fields=countryCode", func(body []byte) string {
		var out struct {
			CountryCode string `json:"countryCode"`
		}
		_ = json.Unmarshal(body, &out)
		return out.CountryCode
	}},
	{"ipwho", "https://ipwho.is/%s?fields=country_code", func(body []byte) string {
		var out struct {
			CountryCode string `json:"country_code"`
		}
		_ = json.Unmarshal(body, &out)
		return out.CountryCode
	}},
	{"ipapi", "https://ipapi.co/%s/country/", func(body []byte) string {
		return strings.TrimSpace(string(body))
	}},
}

// CountryResolver определяет страну по нескольким источникам сразу
type CountryResolver struct {
	db *DB

	mu       sync.Mutex
	cached   string
	cachedAt time.Time
	forAddr  string
}

// NewCountryResolver строит определитель поверх локальной базы
func NewCountryResolver(db *DB) *CountryResolver { return &CountryResolver{db: db} }

// Resolve возвращает код страны. Голосуют локальная база и внешние справочники,
// побеждает код с наибольшим числом совпадений; при ничьей берётся локальная
// база как единственный источник, который не зависит от чужой доступности
func (r *CountryResolver) Resolve(ctx context.Context, addr string) string {
	if strings.TrimSpace(addr) == "" {
		return ""
	}
	r.mu.Lock()
	if r.cached != "" && r.forAddr == addr && time.Since(r.cachedAt) < countryTTL {
		cached := r.cached
		r.mu.Unlock()
		return cached
	}
	r.mu.Unlock()

	local := ""
	if r.db != nil {
		local = normalizeCountry(r.db.Country(addr))
	}
	votes := map[string]int{}
	if local != "" {
		votes[local]++
	}
	for _, code := range askExternal(ctx, addr) {
		votes[code]++
	}
	winner := pickWinner(votes, local)
	if winner == "" {
		return ""
	}
	r.mu.Lock()
	r.cached, r.cachedAt, r.forAddr = winner, time.Now(), addr
	r.mu.Unlock()
	return winner
}

// askExternal опрашивает справочники параллельно: последовательный обход занял
// бы столько же, сколько самый медленный из них, помноженное на их число
func askExternal(ctx context.Context, addr string) []string {
	ctx, cancel := context.WithTimeout(ctx, countryTimeout)
	defer cancel()

	results := make(chan string, len(externalSources))
	var wg sync.WaitGroup
	for _, source := range externalSources {
		wg.Add(1)
		go func(url string, pick func([]byte) string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(url, addr), nil)
			if err != nil {
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
			if err != nil {
				return
			}
			if code := normalizeCountry(pick(body)); code != "" {
				results <- code
			}
		}(source.url, source.pick)
	}
	wg.Wait()
	close(results)

	out := make([]string, 0, len(externalSources))
	for code := range results {
		out = append(out, code)
	}
	return out
}

// pickWinner берёт код с наибольшим числом голосов. Ровный счёт разрешается в
// пользу локальной базы: она не зависит от того, доступен ли чужой сервис
func pickWinner(votes map[string]int, local string) string {
	type row struct {
		code  string
		count int
	}
	rows := make([]row, 0, len(votes))
	for code, count := range votes {
		rows = append(rows, row{code, count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		if rows[i].code == local {
			return true
		}
		if rows[j].code == local {
			return false
		}
		return rows[i].code < rows[j].code
	})
	if len(rows) == 0 {
		return ""
	}
	return rows[0].code
}

func normalizeCountry(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		return ""
	}
	for _, c := range code {
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	return code
}
