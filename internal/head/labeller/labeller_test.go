package labeller

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAPI изображает Anthropic: отдаёт то, что ему велели, и запоминает, что
// ему прислали
type fakeAPI struct {
	srv  *httptest.Server
	sent string
}

func newFakeAPI(t *testing.T, answer string) *fakeAPI {
	t.Helper()
	api := &fakeAPI{}
	api.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		api.sent = string(body)
		_, _ = w.Write([]byte(toolAnswer(answer)))
	}))
	t.Cleanup(api.srv.Close)
	return api
}

func (a *fakeAPI) client() *Client {
	c := NewClient("test-key", "")
	c.SetHTTP(a.srv.Client())
	c.SetEndpoint(a.srv.URL)
	return c
}

// Разметка приходит вызовом инструмента: формат держит схема, и обкладывать
// его прозой модель уже не может
func TestVerdictsComeBackFromTheTool(t *testing.T) {
	api := newFakeAPI(t, `{"verdicts":[{"id":7,"abuse":true,"why":"перебор имён"}]}`)
	got, err := api.client().Label(context.Background(), []Snapshot{{ID: 7, Values: map[string]float64{"requests": 900}}})
	if err != nil {
		t.Fatalf("разметка обосралась: %v", err)
	}
	if len(got) != 1 || got[0].ID != 7 || !got[0].Abuse {
		t.Fatalf("вердикт разобран криво: %+v", got)
	}
}

// В модель уезжают ТОЛЬКО числа. Ни домена, ни адреса, ни имени человека там
// быть не может - это условие всей затеи
func TestOnlyNumbersLeaveTheHead(t *testing.T) {
	api := newFakeAPI(t, `{"verdicts":[]}`)
	_, _ = api.client().Label(context.Background(), []Snapshot{
		{ID: 1, Values: map[string]float64{"requests": 120, "up_ratio": 0.3}},
	})
	for _, forbidden := range []string{"example.com", "subject", "10.0.0.1", "user-"} {
		if strings.Contains(api.sent, forbidden) {
			t.Fatalf("наружу уехало лишнее: %q", forbidden)
		}
	}
	if !strings.Contains(api.sent, "id,requests,up_ratio") || !strings.Contains(api.sent, "1,120,0.3") {
		t.Fatalf("числа до модели не доехали: %s", api.sent)
	}
	// Имена признаков едут ОДИН раз, в шапке: повторять их при каждом числе -
	// значит платить за одно и то же по сорок раз
	if strings.Count(api.sent, "requests") != 2 {
		t.Fatalf("имя признака повторяется лишний раз: %s", api.sent)
	}
}

// Без ключа разметчик не должен даже пытаться
func TestNoKeyNoRequests(t *testing.T) {
	if _, err := NewClient("", "").Label(context.Background(), []Snapshot{{ID: 1}}); err == nil {
		t.Fatal("без ключа разметка не отказалась")
	}
}

type memStore struct {
	rows   []Snapshot
	labels map[uint64]int16
	by     map[uint64]string
	why    map[uint64]string
}

func (m *memStore) Unlabelled(_ string, limit int) ([]Snapshot, error) {
	if len(m.rows) > limit {
		return m.rows[:limit], nil
	}
	return m.rows, nil
}

func (m *memStore) SetLabel(ids []uint64, label int16, by string) error {
	for _, id := range ids {
		m.labels[id] = label
		m.by[id] = by
	}
	return nil
}

func (m *memStore) SetLabelWhy(reasons map[uint64]string, label int16, by string) error {
	if m.why == nil {
		m.why = map[uint64]string{}
	}
	for id, why := range reasons {
		m.labels[id] = label
		m.by[id] = by
		m.why[id] = why
	}
	return nil
}

// Круг разметки раскладывает пачку по меткам и не верит выдуманным id
func TestLoopLabelsOnlyWhatItSent(t *testing.T) {
	api := newFakeAPI(t, `{"verdicts":[{"id":1,"abuse":false},{"id":2,"abuse":true,"why":"имена подряд, ответы крошечные"},{"id":999,"abuse":true}]}`)
	store := &memStore{
		rows:   []Snapshot{{ID: 1, Values: map[string]float64{"requests": 10}}, {ID: 2, Values: map[string]float64{"requests": 5000}}},
		labels: map[uint64]int16{},
		by:     map[uint64]string{},
	}
	NewLoop(api.client(), store, "features-v2", nil).Once(context.Background())

	if store.labels[1] != 0 || store.labels[2] != 1 {
		t.Fatalf("метки разложены криво: %+v", store.labels)
	}
	if _, ok := store.labels[999]; ok {
		t.Fatal("приняли метку на id, которого не отправляли")
	}
	if store.by[1] != By {
		t.Fatalf("разметчик не подписался: %q", store.by[1])
	}
	// Объяснение просим только на обвинения, и оно обязано доехать до базы
	if store.why[2] == "" {
		t.Fatal("обвинение приехало без объяснения")
	}
	if store.why[1] != "" {
		t.Fatalf("на чистого потратили объяснение: %q", store.why[1])
	}
}

type queueStore struct {
	queue  []Snapshot
	rounds int
	labels map[uint64]int16
}

func (q *queueStore) Unlabelled(_ string, limit int) ([]Snapshot, error) {
	q.rounds++
	if len(q.queue) == 0 {
		return nil, nil
	}
	if len(q.queue) > limit {
		out := q.queue[:limit]
		return out, nil
	}
	return q.queue, nil
}

func (q *queueStore) SetLabelWhy(reasons map[uint64]string, label int16, by string) error {
	ids := make([]uint64, 0, len(reasons))
	for id := range reasons {
		ids = append(ids, id)
	}
	return q.SetLabel(ids, label, by)
}

func (q *queueStore) SetLabel(ids []uint64, label int16, _ string) error {
	marked := map[uint64]struct{}{}
	for _, id := range ids {
		q.labels[id] = label
		marked[id] = struct{}{}
	}
	kept := q.queue[:0]
	for _, s := range q.queue {
		if _, done := marked[s.ID]; !done {
			kept = append(kept, s)
		}
	}
	q.queue = kept
	return nil
}

// Очередь разгребается пачками подряд, а не по одной в час: иначе десятки тысяч
// снимков размечались бы месяц, да и кеш промпта окупается только на второй
// пачке и дальше
func TestRoundDrainsSeveralBatches(t *testing.T) {
	total := batchSize*3 + 5
	store := &queueStore{labels: map[uint64]int16{}}
	for i := 1; i <= total; i++ {
		store.queue = append(store.queue, Snapshot{ID: uint64(i), Values: map[string]float64{"requests": 10}})
	}
	// Заглушка отвечает на любые id, которые ей прислали
	api := newFakeAPIFunc(t, verdictsFor)
	NewLoop(api.client(), store, "features-v2", nil).Once(context.Background())

	if len(store.queue) != 0 {
		t.Fatalf("за круг разгребли не всё: осталось %d", len(store.queue))
	}
	if len(store.labels) != total {
		t.Fatalf("размечено %d из %d", len(store.labels), total)
	}
	// Четыре пачки: три полные и хвост
	if store.rounds != 4 {
		t.Fatalf("сходили за пачками %d раз вместо 4", store.rounds)
	}
}
