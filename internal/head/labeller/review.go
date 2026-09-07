package labeller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Второй заход: по обвинениям.
//
// Первый круг судит по голым числам, и там модель видит "обращений 9, доля
// отдачи 0.28" - по такому она не отличит человека, зашедшего в ютуб, от
// чекера, ковыряющего один API. Домены отвечают на это мгновенно.
//
// Наружу они едут ТОЛЬКО по обвинениям, и это осознанный размен: чистых
// большинство, и сливать их походы незачем, а тому, кого мы собрались судить,
// нужен честный разбор, а не приговор по гаданию

// ReviewModel - чем разбираем спорное. Дорогая и умная: обвинений единицы, и
// экономить на них - это как раз то место, где экономить нельзя нахуй
const ReviewModel = "claude-sonnet-5"

// maxReviewDomains - сколько имён показываем. Хвост уходит в тысячи, а картину
// даёт верхушка
const maxReviewDomains = 60

// Domain - куда субъект ходил, как это лежит у нас
type Domain struct {
	Name  string
	Hits  int64
	Bytes uint64
}

// Domains отдаёт походы субъекта за срок
type Domains interface {
	TopDomains(subjectID string, since time.Time, limit int) ([]Domain, error)
}

// Review - окончательный вердикт по одному обвинению
type Review struct {
	Abuse bool   `json:"abuse"`
	Why   string `json:"why"`
}

// SetDomains включает второй заход
func (l *Loop) SetDomains(domains Domains, window time.Duration) {
	l.domains, l.domainWindow = domains, window
}

// review перепроверяет обвинение, показав модели ещё и домены
func (c *Client) review(ctx context.Context, snapshot Snapshot, domains []Domain) (*Review, error) {
	if c.key == "" {
		return nil, fmt.Errorf("labeller: no api key, nothing to review with")
	}
	body, err := json.Marshal(map[string]any{
		"model":      c.reviewModel(),
		"max_tokens": 1024,
		"system": []map[string]any{{
			"type":          "text",
			"text":          reviewPrompt,
			"cache_control": map[string]string{"type": "ephemeral"},
		}},
		"tools":       []map[string]any{reviewTool},
		"tool_choice": map[string]string{"type": "tool", "name": "verdict"},
		"messages": []map[string]string{
			{"role": "user", "content": renderReview(snapshot, domains)},
		},
	})
	if err != nil {
		return nil, err
	}
	raw, err := c.askTool(ctx, body)
	if err != nil {
		return nil, err
	}
	var out Review
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// reviewTool - форма приговора по одному обвинению
var reviewTool = map[string]any{
	"name":        "verdict",
	"description": "Вынести приговор по обвинению",
	"input_schema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"abuse": map[string]any{"type": "boolean"},
			"why": map[string]any{
				"type":        "string",
				"description": "Коротко по-русски, до пятнадцати слов",
			},
		},
		"required": []string{"abuse", "why"},
	},
}

func (c *Client) reviewModel() string {
	if c.reviewModelName != "" {
		return c.reviewModelName
	}
	return ReviewModel
}

// renderReview собирает разбор: числа сверху, домены таблицей снизу
func renderReview(snapshot Snapshot, domains []Domain) string {
	var b strings.Builder
	b.WriteString("Наблюдение:\n")
	names := make([]string, 0, len(snapshot.Values))
	for name := range snapshot.Values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%.4g ", name, snapshot.Values[name])
	}
	b.WriteString("\n\nКуда ходил (имя, обращений, байт):\n")
	for i, d := range domains {
		if i >= maxReviewDomains {
			break
		}
		fmt.Fprintf(&b, "%s %d %d\n", d.Name, d.Hits, d.Bytes)
	}
	return b.String()
}

const reviewPrompt = `Ты разбираешь обвинение против участника бесплатного VPN.
Правила уже сочли его поведение подозрительным по числам. Твоя работа - посмотреть,
куда он на самом деле ходил, и сказать, злоупотребление это или нет.

Злоупотребление: перебор карт и учёток, фишинг, кардинг-лавки, рассылка спама,
сканирование, ботнет и управляющие каналы, торговля доступом.

НЕ злоупотребление: торренты, порно, азартные игры, крипта, обход блокировок,
работа ночью, большой объём, вторая VPN поверх нашей, чужой язык интерфейса.
Человек имеет право на любую легальную скуку.

Сомневаешься - значит НЕ злоупотребление: цена ошибки тут выше, чем цена пропуска.

Ответ отдавай инструментом verdict.`

// reviewAccused перепроверяет обвинения, показав модели домены.
//
// Оправданные уходят в чистые: метка обвинения, снятая разбором, в обучение
// попасть не должна, иначе бустинг выучит именно ту ошибку, которую мы только
// что поймали
func (l *Loop) reviewAccused(ctx context.Context, batch []Snapshot, dirty map[uint64]string) map[uint64]string {
	if l.domains == nil || len(dirty) == 0 {
		return dirty
	}
	window := l.domainWindow
	if window <= 0 {
		window = 7 * 24 * time.Hour
	}
	bySnapshot := make(map[uint64]Snapshot, len(batch))
	for _, s := range batch {
		bySnapshot[s.ID] = s
	}
	kept := make(map[uint64]string, len(dirty))
	var cleared []uint64
	for id, why := range dirty {
		snapshot, ok := bySnapshot[id]
		if !ok {
			kept[id] = why
			continue
		}
		domains, err := l.domains.TopDomains(snapshot.SubjectID, time.Now().Add(-window), maxReviewDomains)
		if err != nil || len(domains) == 0 {
			// Доменов нет - судить остаётся по числам, как и раньше
			kept[id] = why
			continue
		}
		verdict, err := l.client.review(ctx, snapshot, domains)
		if err != nil {
			if l.log != nil {
				l.log("labeller: the review of %d failed: %v", id, err)
			}
			kept[id] = why
			continue
		}
		if verdict.Abuse {
			kept[id] = verdict.Why
			continue
		}
		cleared = append(cleared, id)
		if l.log != nil {
			l.log("labeller: the charge against %d was dropped: %s", id, verdict.Why)
		}
	}
	if len(cleared) > 0 {
		if err := l.store.SetLabel(cleared, 0, By); err != nil && l.log != nil {
			l.log("labeller: dropped charges were not stored: %v", err)
		}
	}
	return kept
}
