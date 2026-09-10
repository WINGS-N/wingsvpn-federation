package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeRegistry изображает IANA и реестр разом: bootstrap отдаёт сам себя, а
// домены отвечают заранее заданной датой
func fakeRegistry(t *testing.T, registered map[string]string) (*Client, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap" {
			_, _ = w.Write([]byte(`{"services":[[["example","co.uk","uk"],["` + baseOf(r) + `"]]]}`))
			return
		}
		hits++
		name := r.URL.Path[len("/domain/"):]
		date, ok := registered[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"events":[{"eventAction":"last changed","eventDate":"2026-01-01T00:00:00Z"},` +
			`{"eventAction":"registration","eventDate":"` + date + `"}]}`))
	}))
	t.Cleanup(srv.Close)

	client := New()
	client.SetHTTP(srv.Client())
	// Список серверов подсовываем руками: в тесте лезть на data.iana.org нельзя
	client.services = map[string]string{
		"example": srv.URL + "/",
		"co.uk":   srv.URL + "/",
		"uk":      srv.URL + "/",
	}
	client.fetchedAt = time.Now()
	return client, &hits
}

func baseOf(r *http.Request) string { return "http://" + r.Host + "/" }

func TestRegisteredReadsTheRegistrationEvent(t *testing.T) {
	client, _ := fakeRegistry(t, map[string]string{"shop.example": "2026-08-20T10:00:00Z"})
	got, err := client.Registered(context.Background(), "pay.shop.example")
	if err != nil {
		t.Fatalf("реестр не ответил: %v", err)
	}
	if got.Format("2006-01-02") != "2026-08-20" {
		t.Fatalf("дата не та: %v", got)
	}
}

// У example.co.uk регистрируемое имя - example.co.uk, а НЕ co.uk: обрезание по
// двум последним меткам спросило бы реестр про саму зону
func TestRegistrableNameKeepsTwoLevelZones(t *testing.T) {
	if got := normalize("www.example.co.uk"); got != "example.co.uk" {
		t.Fatalf("имя порезали не там: %q", got)
	}
	if got := normalize("a.b.shop.example"); got != "shop.example" {
		t.Fatalf("имя порезали не там: %q", got)
	}
	if got := normalize("localhost"); got != "" {
		t.Fatalf("одинокая метка прошла как домен: %q", got)
	}
}

type memAges struct {
	registered map[string]time.Time
	checked    map[string]time.Time
}

func (m *memAges) Age(domain string) (time.Time, time.Time, bool) {
	checked, ok := m.checked[domain]
	if !ok {
		return time.Time{}, time.Time{}, false
	}
	return m.registered[domain], checked, true
}

func (m *memAges) Put(domain string, registered, checked time.Time) error {
	m.registered[domain] = registered
	m.checked[domain] = checked
	return nil
}

func (m *memAges) PutMiss(domain string, checked time.Time) error {
	m.checked[domain] = checked
	return nil
}

// Второй раз про то же имя реестр спрашивать нельзя: домен стареет медленно, а
// лимиты у реестров злые
func TestResolverAsksTheRegistryOnce(t *testing.T) {
	client, hits := fakeRegistry(t, map[string]string{"shop.example": "2026-08-20T10:00:00Z"})
	store := &memAges{registered: map[string]time.Time{}, checked: map[string]time.Time{}}
	resolver := NewResolver(client, store, nil)
	resolver.SetNow(func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) })

	days, ok := resolver.AgeDays(context.Background(), "shop.example")
	if !ok || days < 13 || days > 15 {
		t.Fatalf("возраст посчитан неверно: %.1f ok=%v", days, ok)
	}
	if _, ok := resolver.AgeDays(context.Background(), "www.shop.example"); !ok {
		t.Fatal("поддомен не нашёл ответ по своему домену")
	}
	if *hits != 1 {
		t.Fatalf("сходили в реестр %d раз вместо одного", *hits)
	}
}

// Отказ реестра - это "хуй знает", а не "домен свежий". И долбиться повторно
// на каждом круге тоже нельзя
func TestResolverRemembersAMiss(t *testing.T) {
	client, hits := fakeRegistry(t, map[string]string{})
	store := &memAges{registered: map[string]time.Time{}, checked: map[string]time.Time{}}
	resolver := NewResolver(client, store, nil)
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	resolver.SetNow(func() time.Time { return now })

	if _, ok := resolver.AgeDays(context.Background(), "nobody.example"); ok {
		t.Fatal("отказ приняли за возраст")
	}
	if _, ok := resolver.AgeDays(context.Background(), "nobody.example"); ok {
		t.Fatal("отказ приняли за возраст")
	}
	if *hits != 1 {
		t.Fatalf("на отказ сходили %d раз", *hits)
	}
}

// За круг разрешено конечное число запросов, иначе один активный человек
// выжирает лимит реестра на весь флот
func TestResolverKeepsARoundBudget(t *testing.T) {
	registered := map[string]string{}
	for i := 0; i < perRound+10; i++ {
		registered[string(rune('a'+i%26))+"x.example"] = "2020-01-01T00:00:00Z"
	}
	client, hits := fakeRegistry(t, registered)
	store := &memAges{registered: map[string]time.Time{}, checked: map[string]time.Time{}}
	resolver := NewResolver(client, store, nil)
	resolver.StartRound()
	for name := range registered {
		resolver.AgeDays(context.Background(), name)
	}
	if *hits > perRound {
		t.Fatalf("за круг сходили в реестр %d раз при потолке %d", *hits, perRound)
	}
}
