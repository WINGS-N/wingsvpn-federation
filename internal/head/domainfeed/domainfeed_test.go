package domainfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Списки приходят в трёх видах разом, и жевать надо все три
func TestParseEatsEveryShapeOfList(t *testing.T) {
	body := strings.Join([]string{
		"# комментарий",
		"! тоже комментарий",
		"0.0.0.0 bad-shop.example",
		"127.0.0.1 localhost",
		"127.0.0.1 broadcasthost",
		"plain-evil.example",
		"https://phish.example/login/verify?id=1",
		"0.0.0.0 dup.example",
		"dup.example",
		"   ",
		"0.0.0.0 with-comment.example # свежак",
		"не_домен",
	}, "\n")

	got, err := Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("разбор обосрался: %v", err)
	}
	want := []string{"bad-shop.example", "plain-evil.example", "phish.example", "dup.example", "with-comment.example"}
	if len(got) != len(want) {
		t.Fatalf("имён %d вместо %d: %v", len(got), len(want), got)
	}
	for i, name := range want {
		if got[i] != name {
			t.Fatalf("на месте %d стоит %q вместо %q", i, got[i], name)
		}
	}
}

// Поддомен спалившегося домена - это тот же домен, а вот до зоны подниматься
// нельзя ни в коем случае
func TestKindMatchesSubdomainsButNotTheZone(t *testing.T) {
	pool := NewPool(nil, nil)
	pool.apply(Feed{ID: "t", Kind: fedpb.AbuseKind_ABUSE_KIND_MALWARE}, []string{"bad-shop.example"})

	if _, ok := pool.Kind("login.bad-shop.example"); !ok {
		t.Fatal("поддомен спалившегося домена не опознали")
	}
	if _, ok := pool.Kind("bad-shop.example"); !ok {
		t.Fatal("сам домен не опознали")
	}
	if _, ok := pool.Kind("good.example"); ok {
		t.Fatal("обвинили посторонний домен")
	}
	if _, ok := pool.Kind("example"); ok {
		t.Fatal("обвинили целую зону")
	}
}

type memFeedStore struct {
	domains map[string][]string
}

func (m *memFeedStore) Load(feedID string) ([]string, time.Time, error) {
	return m.domains[feedID], time.Now(), nil
}

func (m *memFeedStore) Save(feedID string, domains []string, _ time.Time) error {
	m.domains[feedID] = domains
	return nil
}

// Источник лёг - набор остаётся тем, что был. Забыть всё и пустить мошенника
// потому что чужой сервер прилёг, было бы отменной дуростью
func TestDeadSourceKeepsTheOldSet(t *testing.T) {
	alive := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !alive {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("0.0.0.0 bad-shop.example\n"))
	}))
	defer srv.Close()

	store := &memFeedStore{domains: map[string][]string{}}
	pool := NewPool(store, nil)
	pool.SetHTTP(srv.Client())
	pool.SetFeeds([]Feed{{ID: "t", URL: srv.URL, Kind: fedpb.AbuseKind_ABUSE_KIND_MALWARE}})

	pool.Once(context.Background())
	if pool.Size() != 1 {
		t.Fatalf("список не заехал: %d", pool.Size())
	}

	alive = false
	pool.Once(context.Background())
	if _, ok := pool.Kind("bad-shop.example"); !ok {
		t.Fatal("на мёртвом источнике забыли всё, что знали")
	}

	// И после рестарта башка обязана встать с тем же набором
	restarted := NewPool(store, nil)
	restarted.SetFeeds([]Feed{{ID: "t", URL: srv.URL, Kind: fedpb.AbuseKind_ABUSE_KIND_MALWARE}})
	restarted.Restore()
	if _, ok := restarted.Kind("bad-shop.example"); !ok {
		t.Fatal("после рестарта набор пустой")
	}
}
