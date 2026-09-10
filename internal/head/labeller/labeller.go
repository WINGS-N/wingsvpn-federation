// Package labeller размечает накопленные векторы чужой моделью.
//
// Без меток бустинг мёртв нахуй: векторы копятся месяцами, а учить его не на
// чем. Руками разметить десятки тысяч снимков никто не будет, поэтому пачки
// уходят к Claude, а человек проверяет выборочно.
//
// Наружу едут ТОЛЬКО ЧИСЛА. Ни домена, ни адреса, ни имени человека в векторе
// нет и не будет: это условие всей затеи, а не пожелание. Уходит форма
// поведения - сколько имён в час, какая доля долгих соединений, есть ли суточный
// провал - и по ней модель говорит, похоже это на живого человека или на ферму
package labeller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// endpoint - куда стучимся
const endpoint = "https://api.anthropic.com/v1/messages"

// apiVersion - версия протокола, которую требует заголовок
const apiVersion = "2023-06-01"

// DefaultModel - чем размечаем пачки. Дешёвая и быстрая: разметка это конвейер
// на десятки тысяч строк, и гонять по нему дорогую модель - выкидывать деньги.
// Дорогая остаётся на хвосте, где спорно, и на объяснениях
const DefaultModel = "claude-haiku-4-5-20251001"

// batchSize - сколько снимков отдаём за один заход. Больше сотни - и модель
// начинает путать строки местами, меньше десятка - платим за приветствие чаще,
// чем за работу
const batchSize = 40

// requestTimeout - модель думает, но не вечно
const requestTimeout = 2 * time.Minute

// maxTokens - потолок на ответ. Сорок строк вида id плюс да/нет это меньше
// тысячи токенов, но потолок берём с запасом: упрётся в него - JSON оборвётся
// на полуслове, и вся пачка улетит нахуй вместе с оплаченным заходом
const maxTokens = 8192

// Snapshot - один вектор, который надо разметить
type Snapshot struct {
	ID uint64
	// SubjectID нужен второму заходу: по нему поднимаются домены обвинённого
	SubjectID string
	Values    map[string]float64
}

// Store - что разметчику нужно от базы
type Store interface {
	// Unlabelled отдаёт неразмеченное, самое свежее первым
	Unlabelled(version string, limit int) ([]Snapshot, error)
	// SetLabel помечает снимки. by говорит, кто разметил, чтобы человеческую
	// метку потом не затёрла машинная
	SetLabel(ids []uint64, label int16, by string) error
	// SetLabelWhy - то же самое, но с объяснением на каждый снимок. Нужно, чтобы
	// человек при выборочной проверке видел, ЗА ЧТО модель обвинила, а не гадал
	// по строке из двадцати цифр
	SetLabelWhy(reasons map[uint64]string, label int16, by string) error
}

// Client ходит в Anthropic
type Client struct {
	key   string
	model string
	// reviewModelName - модель для разбора обвинений. Дорогая, зато их единицы
	reviewModelName string
	http            *http.Client
	endpoint        string
}

// SetReviewModel задаёт модель для второго захода
func (c *Client) SetReviewModel(model string) { c.reviewModelName = strings.TrimSpace(model) }

func NewClient(key, model string) *Client {
	if strings.TrimSpace(model) == "" {
		model = DefaultModel
	}
	return &Client{
		key:   strings.TrimSpace(key),
		model: model,
		http:  &http.Client{Timeout: requestTimeout},
	}
}

// SetHTTP подменяет клиента, чтобы тесты не ходили в живой API
func (c *Client) SetHTTP(client *http.Client) { c.http = client }

// SetEndpoint подменяет адрес. Тоже только для тестов
func (c *Client) SetEndpoint(url string) { c.endpoint = url }

// Verdict - что модель сказала про один снимок.
//
// Объяснение просим ТОЛЬКО на обвинения. Проверять человеку надо именно их, а
// сорок пояснений на пачку - это выход, который у модели дороже входа впятеро,
// и текст, в котором в двадцати случаях из двадцати написано "обычный человек"
type Verdict struct {
	ID    uint64 `json:"id"`
	Abuse bool   `json:"abuse"`
	Why   string `json:"why,omitempty"`
}

// Label спрашивает модель про пачку снимков
func (c *Client) Label(ctx context.Context, snapshots []Snapshot) ([]Verdict, error) {
	if c.key == "" {
		return nil, fmt.Errorf("labeller: no api key, nothing to label with")
	}
	if len(snapshots) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(map[string]any{
		"model":      c.model,
		"max_tokens": maxTokens,
		// Промпт помечен под кеш: он не меняется от пачки к пачке, и когда за
		// круг их уходит несколько, со второй вход дешевеет вчетверо
		"system": []map[string]any{{
			"type":          "text",
			"text":          systemPrompt,
			"cache_control": map[string]string{"type": "ephemeral"},
		}},
		// Ответ идёт инструментом, а не текстом: модель любит обложить JSON
		// прозой, и тогда его приходится выковыривать из болтовни, а на длинной
		// пачке ещё и спасать оборванное
		"tools":       []map[string]any{labelTool},
		"tool_choice": map[string]string{"type": "tool", "name": "label"},
		"messages": []map[string]string{
			{"role": "user", "content": renderBatch(snapshots)},
		},
	})
	if err != nil {
		return nil, err
	}
	raw, err := c.askTool(ctx, body)
	if err != nil {
		return nil, err
	}
	var out struct {
		Verdicts []Verdict `json:"verdicts"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Verdicts, nil
}

// labelTool - форма ответа разметчика. Схема и есть требование к формату,
// поэтому объяснять его словами в промпте больше не нужно
var labelTool = map[string]any{
	"name":        "label",
	"description": "Отдать разметку присланных наблюдений",
	"input_schema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"verdicts": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":    map[string]any{"type": "integer"},
						"abuse": map[string]any{"type": "boolean"},
						"why": map[string]any{
							"type":        "string",
							"description": "Только при abuse=true, до десяти слов",
						},
					},
					"required": []string{"id", "abuse"},
				},
			},
		},
		"required": []string{"verdicts"},
	},
}

// askTool шлёт запрос и достаёт вход вызванного инструмента
func (c *Client) askTool(ctx context.Context, body []byte) ([]byte, error) {
	answer, err := c.raw(ctx, body)
	if err != nil {
		return nil, err
	}
	for _, part := range answer.Content {
		if part.Type == "tool_use" && len(part.Input) > 0 {
			return part.Input, nil
		}
	}
	return nil, fmt.Errorf("labeller: the model did not call the tool")
}

// answer - ответ модели, как он приходит по проводу
type answer struct {
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
}

// raw шлёт запрос и отдаёт разобранный ответ
func (c *Client) raw(ctx context.Context, body []byte) (*answer, error) {
	url := c.endpoint
	if url == "" {
		url = endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", c.key)
	req.Header.Set("anthropic-version", apiVersion)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("labeller: the model answered %d", resp.StatusCode)
	}
	var out answer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// renderBatch собирает пачку таблицей: имена признаков идут ОДИН раз в шапке, а
// дальше только числа.
//
// Раньше имя ехало при каждом числе, и на пачке в сорок строк это восемнадцать
// килобайт вместо шести: две трети оплаченного входа уходили на то, чтобы триста
// раз повторить слово bytes_per_request.
//
// Порядок признаков устойчивый, иначе модель видит каждый раз новую форму и
// начинает путаться
func renderBatch(snapshots []Snapshot) string {
	names := map[string]struct{}{}
	for _, s := range snapshots {
		for name := range s.Values {
			names[name] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)

	var b strings.Builder
	b.WriteString("id," + strings.Join(ordered, ",") + "\n")
	for _, s := range snapshots {
		fmt.Fprintf(&b, "%d", s.ID)
		for _, name := range ordered {
			fmt.Fprintf(&b, ",%.4g", s.Values[name])
		}
		b.WriteString("\n")
	}
	return b.String()
}

// systemPrompt объясняет модели, что за числа она видит и чего от неё хотят.
//
// Порог осторожности задан прямо: цена ошибки несимметрична. Пропущенный
// мошенник стоит нам жалобы, а невиновный, помеченный как ферма, теряет доступ
const systemPrompt = `Ты размечаешь обезличенные наблюдения за трафиком бесплатного VPN.

Данные приходят таблицей: первая строка - имена столбцов, дальше по строке на участника.
Первый столбец - id наблюдения, остальные - числа. Никаких доменов и адресов там нет.

Признаки:
- requests: всего обращений; domains: сколько разных имён; domains_per_hour: скорость появления новых имён
- bytes_per_request: средний размер обмена; up_ratio: доля отдачи; long_lived_share: доля долгих соединений
- quiet_hours: самая длинная пауза в сутках; active_hours: в скольких часах была активность; spread_hours: на сколько часов размазано
- random_name_share: доля имён, похожих на сгенерированные автоматом
- no_domain_share: доля соединений на голый адрес; distinct_bare_peers: сколько таких адресов
- relay_port_hits: соединения на порт между почтовыми серверами; submission_hits и submission_targets: отправка почты и на сколько разных серверов
- peer_port_hits: обмен по портам bittorrent; ports_touched: сколько разных портов задето
- distinct_prints: сколько разных TLS-стеков; top_print_share: доля самого частого стека
- fresh_domains и fresh_domain_share: сколько имён моложе месяца и какая их доля

Часть случаев уже отсеяна порогами до тебя, и в присланных данных их нет.
Твоя работа - остальное.

Ставь abuse=true в этих случаях и только в них:
1. Перебор: domains_per_hour больше 120 ПРИ bytes_per_request меньше 1000 и long_lived_share равном нулю.
2. Рассылка: submission_targets больше 8, или relay_port_hits больше нуля.
3. Скан портов: ports_touched больше 25.
4. Управляющий канал: random_name_share выше 0.25 при заметном числе имён.

Всё остальное - чисто. В частности НЕ являются злоупотреблением сами по себе:
- торренты, даже когда peer_port_hits в тысячах, no_domain_share выше 0.8 и distinct_bare_peers
  под сотни. Это обычная раздача файлов, а не скан: у скана нет долгих соединений, а у торрента
  long_lived_share высокий;
- большой объём и высокий up_ratio;
- работа ночью и любой сдвиг суток: quiet_hours и active_hours говорят лишь о графике человека;
- свежие домены сами по себе, если нет ни перебора, ни сгенерированных имён.

Живой человек выглядит рвано: десятки имён, жирные ответы, есть долгие соединения.

Сомневаешься - ставь abuse=false. Ошибка в эту сторону стоит нам жалобы, ошибка в другую
отнимает у человека доступ.

Ответ отдавай инструментом label: строка на каждый присланный id. Поле why
заполняй ТОЛЬКО при abuse=true.`
