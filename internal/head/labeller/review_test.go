package labeller

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeDomains struct {
	rows []Domain
}

func (f fakeDomains) TopDomains(string, time.Time, int) ([]Domain, error) { return f.rows, nil }

// Обвинение по голым числам - ещё не приговор: взгляд на домены половину таких
// снимает, и снятое обязано уйти в чистые, а не остаться меткой обвинения
func TestReviewClearsAnAccusationByDomains(t *testing.T) {
	var sawDomains bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		if strings.Contains(body, "\"name\":\"verdict\"") {
			// Второй заход: домены обязаны доехать до модели
			sawDomains = strings.Contains(body, "rutracker.org")
			_, _ = w.Write([]byte(`{"content":[{"type":"tool_use","name":"verdict",` +
				`"input":{"abuse":false,"why":"торренты, не злоупотребление"}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"tool_use","name":"label",` +
			`"input":{"verdicts":[{"id":1,"abuse":true,"why":"голые адреса"}]}}]}`))
	}))
	defer srv.Close()

	client := NewClient("test-key", "")
	client.SetHTTP(srv.Client())
	client.SetEndpoint(srv.URL)

	store := &memStore{
		rows:   []Snapshot{{ID: 1, SubjectID: "user-1", Values: map[string]float64{"peer_port_hits": 3900}}},
		labels: map[uint64]int16{},
		by:     map[uint64]string{},
	}
	loop := NewLoop(client, store, "features-v2", nil)
	loop.SetDomains(fakeDomains{rows: []Domain{{Name: "rutracker.org", Hits: 40, Bytes: 1 << 30}}}, time.Hour)
	loop.Once(context.Background())

	if !sawDomains {
		t.Fatal("домены до разбора не доехали")
	}
	if store.labels[1] != 0 {
		t.Fatalf("оправданный остался обвинённым: %v", store.labels)
	}
}

// Доменов нет - судим по числам, как и раньше, а не оправдываем молча
func TestReviewKeepsAccusationWithoutDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"content":[{"type":"tool_use","name":"label",` +
			`"input":{"verdicts":[{"id":1,"abuse":true,"why":"перебор"}]}}]}`))
	}))
	defer srv.Close()

	client := NewClient("test-key", "")
	client.SetHTTP(srv.Client())
	client.SetEndpoint(srv.URL)

	store := &memStore{
		rows:   []Snapshot{{ID: 1, SubjectID: "user-1", Values: map[string]float64{"domains_per_hour": 500}}},
		labels: map[uint64]int16{},
		by:     map[uint64]string{},
	}
	loop := NewLoop(client, store, "features-v2", nil)
	loop.SetDomains(fakeDomains{}, time.Hour)
	loop.Once(context.Background())

	if store.labels[1] != 1 {
		t.Fatalf("обвинение потерялось без доменов: %v", store.labels)
	}
}
