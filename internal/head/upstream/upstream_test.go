package upstream

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const vless = "vless://uuid-1@1.2.3.4:443?type=tcp&security=reality#Продавец Germany"

// Единого формата у подписок нет: кто-то отдаёт список строк, кто-то base64.
// Спорить с чужим форматом бессмысленно, надо жрать оба
func TestParsesBothPlainAndBase64Bodies(t *testing.T) {
	plain := vless + "\n" + strings.Replace(vless, "uuid-1", "uuid-2", 1)
	if got := ParseLinks([]byte(plain)); len(got) != 2 {
		t.Fatalf("из списка достали %d ссылок, а их две", len(got))
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	if got := ParseLinks([]byte(encoded)); len(got) != 2 {
		t.Fatalf("из base64 достали %d ссылок, а их две", len(got))
	}
	// Мусор и комментарии в чужом теле попадаются всегда
	dirty := "# заметка продавца\n\nhttps://example.org/page\n" + vless
	if got := ParseLinks([]byte(dirty)); len(got) != 1 {
		t.Fatalf("из мусорного тела достали %d ссылок, а годная одна", len(got))
	}
}

// Башка обязана представляться одним и тем же устройством: меняющийся
// идентификатор для продавца выглядит как толпа новой железки
func TestFetchAlwaysSendsTheSameDevice(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("x-hwid"))
		_, _ = w.Write([]byte(vless))
	}))
	defer srv.Close()

	pool := NewPool(nil, nil)
	pool.Enable(true)
	if err := pool.Put(Source{ID: "s1", URL: srv.URL, DeviceID: "fixed-hwid", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.Refresh(context.Background())
	pool.Refresh(context.Background())

	if len(seen) != 2 || seen[0] != "fixed-hwid" || seen[1] != "fixed-hwid" {
		t.Fatalf("продавец увидел устройства %v", seen)
	}
	if links := pool.List()[0].Links; len(links) != 1 {
		t.Fatalf("тело не разобралось: %v", links)
	}
}

// Моргнувший продавец не повод выкидывать людей с рабочих ссылок
func TestFailedRefreshKeepsTheOldBody(t *testing.T) {
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(vless))
	}))
	defer srv.Close()

	pool := NewPool(nil, nil)
	pool.Enable(true)
	if err := pool.Put(Source{ID: "s1", URL: srv.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.Refresh(context.Background())
	fail = true
	pool.Refresh(context.Background())

	source := pool.List()[0]
	if len(source.Links) != 1 {
		t.Fatal("после отказа продавца ссылки потерялись")
	}
	if source.LastError == "" {
		t.Fatal("отказ не записан, и понять причину будет неоткуда")
	}
}

// Потолок купленного тарифа надо соблюдать: раздашь толпе - продавец увидит
// толпу и забанит аккаунт
func TestSourceIsNotHandedOutBeyondItsCap(t *testing.T) {
	pool := NewPool(nil, nil)
	pool.Enable(true)
	if err := pool.Put(Source{
		ID: "s1", Vendor: "Куплено", URL: "https://example.org/sub",
		MaxClients: 2, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	pool.sources["s1"].Links = []string{vless, strings.Replace(vless, "uuid-1", "uuid-2", 1)}

	assigner := NewAssigner(pool)
	if got := assigner.For("user-1"); len(got) != 1 {
		t.Fatal("первому источник не достался")
	}
	if got := assigner.For("user-2"); len(got) != 1 {
		t.Fatal("второму источник не достался")
	}
	if got := assigner.For("user-3"); len(got) != 0 {
		t.Fatal("третий пролез за потолок тарифа")
	}
	// Уже закреплённый человек своё не теряет
	if got := assigner.For("user-1"); len(got) != 1 {
		t.Fatal("закрепление сорвалось на повторном заходе")
	}
}

// Список серверов не должен плясать от захода к заходу
func TestAssignmentIsStable(t *testing.T) {
	pool := NewPool(nil, nil)
	pool.Enable(true)
	if err := pool.Put(Source{ID: "s1", URL: "https://example.org/sub", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.sources["s1"].Links = []string{
		vless,
		strings.Replace(vless, "uuid-1", "uuid-2", 1),
		strings.Replace(vless, "uuid-1", "uuid-3", 1),
	}
	assigner := NewAssigner(pool)
	first := assigner.For("user-1")
	second := assigner.For("user-1")
	if len(first) != 1 || first[0].Raw != second[0].Raw {
		t.Fatal("человеку выдали разные серверы на двух заходах")
	}
}

// Закрепление отпускается, когда человек перестал ходить: иначе места в тарифе
// заняты навсегда теми, кто ушёл
func TestHoldExpires(t *testing.T) {
	pool := NewPool(nil, nil)
	pool.Enable(true)
	if err := pool.Put(Source{ID: "s1", URL: "https://example.org/sub", MaxClients: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.sources["s1"].Links = []string{vless}

	now := time.Now()
	assigner := NewAssigner(pool)
	assigner.now = func() time.Time { return now }
	if got := assigner.For("user-1"); len(got) != 1 {
		t.Fatal("первому не досталось")
	}
	if got := assigner.For("user-2"); len(got) != 0 {
		t.Fatal("второй пролез мимо потолка")
	}
	now = now.Add(holdFor + time.Minute)
	if got := assigner.For("user-2"); len(got) != 1 {
		t.Fatal("место не освободилось после того, как первый пропал")
	}
}

// Имя продавца в списке у человека выглядит посторонним сервером
func TestRenameReplacesTheSellersLabel(t *testing.T) {
	got := Rename(vless, "Germany 2")
	if !strings.HasSuffix(got, "#Germany%202") {
		t.Fatalf("имя не подставилось: %s", got)
	}
	if strings.Contains(got, "Продавец") {
		t.Fatal("чужое имя осталось в ссылке")
	}
	if bare := Rename("vless://uuid@1.2.3.4:443", "Germany 2"); !strings.HasSuffix(bare, "#Germany%202") {
		t.Fatalf("ссылка без имени не получила его: %s", bare)
	}
}

// fakeRelay изображает ноду, которая ходит наружу вместо башки
type fakeRelay struct {
	body    []byte
	err     error
	headers map[string]string
	calls   int
}

func (f *fakeRelay) FetchVia(_ context.Context, _ string, headers map[string]string, _ uint32) ([]byte, error) {
	f.calls++
	f.headers = headers
	return f.body, f.err
}

// Башке прикрыли адрес - идём через ноды, и человек этого даже не замечает
func TestBlockedHeadFallsBackToNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Ровно то, как выглядит блокировка: соединение принято и обрублено
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	relay := &fakeRelay{body: []byte(vless)}
	pool := NewPool(nil, nil)
	pool.Enable(true)
	pool.SetRelay(relay)
	if err := pool.Put(Source{ID: "s1", URL: srv.URL, DeviceID: "fixed-hwid", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.Refresh(context.Background())

	source := pool.List()[0]
	if len(source.Links) != 1 {
		t.Fatalf("через ноду ничего не принесли: %+v", source)
	}
	if relay.calls != 1 {
		t.Fatalf("ноду дёрнули %d раз", relay.calls)
	}
	// С ноды представляемся тем же устройством, иначе продавец увидит новую железку
	if relay.headers["x-hwid"] != "fixed-hwid" {
		t.Fatalf("нода пошла под чужим устройством: %v", relay.headers)
	}
}

// Пока свой адрес работает, ноды дёргать незачем
func TestWorkingHeadDoesNotBotherNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vless))
	}))
	defer srv.Close()

	relay := &fakeRelay{body: []byte(vless)}
	pool := NewPool(nil, nil)
	pool.Enable(true)
	pool.SetRelay(relay)
	if err := pool.Put(Source{ID: "s1", URL: srv.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.Refresh(context.Background())
	if relay.calls != 0 {
		t.Fatal("ноду дёрнули, хотя башка справилась сама")
	}
}

// Не смогли ни сами, ни через ноду - остаёмся на прошлом теле и говорим, что
// сломалось у НАС: чинить надо это, а не то, что заодно не сложилось у ноды
func TestBothPathsFailedKeepsTheOldBody(t *testing.T) {
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(vless))
	}))
	defer srv.Close()

	pool := NewPool(nil, nil)
	pool.Enable(true)
	pool.SetRelay(&fakeRelay{err: errors.New("нода тоже не смогла")})
	if err := pool.Put(Source{ID: "s1", URL: srv.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.Refresh(context.Background())
	fail = true
	pool.Refresh(context.Background())

	source := pool.List()[0]
	if len(source.Links) != 1 {
		t.Fatal("ссылки потерялись, хотя прошлое тело было рабочим")
	}
	if !strings.Contains(source.LastError, "403") {
		t.Fatalf("записали не ту причину: %s", source.LastError)
	}
}

// Пока владелец не включил раздачу купленного, её нет вообще: ни походов к
// продавцу, ни ссылок людям
func TestUpstreamsAreOffUntilTurnedOn(t *testing.T) {
	var asked int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked++
		_, _ = w.Write([]byte(vless))
	}))
	defer srv.Close()

	pool := NewPool(nil, nil)
	if pool.Enabled() {
		t.Fatal("раздача купленного включена по умолчанию")
	}
	if err := pool.Put(Source{ID: "s1", URL: srv.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.Refresh(context.Background())
	if asked != 0 {
		t.Fatal("сходили к продавцу при выключенном рубильнике")
	}
	if got := NewAssigner(pool).For("user-1"); len(got) != 0 {
		t.Fatal("ссылки раздались при выключенном рубильнике")
	}

	pool.Enable(true)
	pool.Refresh(context.Background())
	if asked != 1 {
		t.Fatalf("после включения к продавцу сходили %d раз", asked)
	}
}

// Пока доверия нет, за пределы своего флота человека не пускают: там Oracle
// слеп, и его художества прилетят на наш аккаунт
func TestUntrustedSubjectGetsNoUpstream(t *testing.T) {
	pool := NewPool(nil, nil)
	pool.Enable(true)
	if err := pool.Put(Source{ID: "s1", Vendor: "Куплено", URL: "https://example.org/sub", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.sources["s1"].Links = []string{vless}

	assigner := NewAssigner(pool)
	assigner.SetTrust(onlyTrusted{"user-1": true})
	if got := assigner.For("user-1"); len(got) != 1 {
		t.Fatal("доверенному не досталось")
	}
	if got := assigner.For("user-2"); len(got) != 0 {
		t.Fatal("недоверенного пустили в слепую зону")
	}
}

type onlyTrusted map[string]bool

func (o onlyTrusted) TrustedForUpstream(subjectID string) bool { return o[subjectID] }

// Имя сервера у человека должно называть вендора, а не быть безымянной строкой
func TestServerNameCarriesTheVendor(t *testing.T) {
	pool := NewPool(nil, nil)
	pool.Enable(true)
	if err := pool.Put(Source{ID: "s1", Vendor: "Вендор", URL: "https://example.org/sub", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.sources["s1"].Links = []string{vless, strings.Replace(vless, "uuid-1", "uuid-2", 1)}

	got := NewAssigner(pool).For("user-1")
	if len(got) != 1 {
		t.Fatalf("ссылок %d", len(got))
	}
	if !strings.HasPrefix(got[0].Name, "Вендор") {
		t.Fatalf("имя не называет вендора: %s", got[0].Name)
	}
	fragment := got[0].Raw[strings.LastIndex(got[0].Raw, "#")+1:]
	decoded, err := url.PathUnescape(fragment)
	if err != nil || decoded != got[0].Name {
		t.Fatalf("имя не подставилось в саму ссылку: %s", got[0].Raw)
	}
}

// JSON тоже бывает подпиской, и ссылки в нём лежат где попало
func TestParsesJSONBodies(t *testing.T) {
	for name, body := range map[string]string{
		"массив строк": `["` + vless + `"]`,
		"поле links":   `{"links": ["` + vless + `"]}`,
		"целый конфиг": `{"outbounds": [{"type": "direct"}, {"tag": "a", "link": "` + vless + `"}]}`,
		"в base64":     base64.StdEncoding.EncodeToString([]byte(`["` + vless + `"]`)),
	} {
		if got := ParseLinks([]byte(body)); len(got) != 1 {
			t.Fatalf("%s: достали %d ссылок", name, len(got))
		}
	}
}

type verdicts map[string]struct {
	score int
	full  bool
}

func (v verdicts) Confidence(subjectID string) (int, bool) {
	got := v[subjectID]
	return got.score, got.full
}

// В слепую зону пускаем только тех, кто чист почти под сотню: там Oracle не
// увидит ни одного его художества, пока не прилетит жалоба продавца
func TestOnlyNearlySpotlessGoUpstream(t *testing.T) {
	pool := NewPool(nil, nil)
	pool.Enable(true)
	if err := pool.Put(Source{ID: "s1", Vendor: "Вендор", URL: "https://example.org/sub", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool.sources["s1"].Links = []string{vless}

	assigner := NewAssigner(pool)
	assigner.SetTrust(TrustAbove(MinConfidence, verdicts{
		"clean":      {score: 100, full: true},
		"borderline": {score: MinConfidence, full: true},
		"slightly":   {score: MinConfidence - 1, full: true},
		"reduced":    {score: 100, full: false},
	}))

	for _, id := range []string{"clean", "borderline"} {
		if got := assigner.For(id); len(got) != 1 {
			t.Fatalf("%s не пустили, хотя доверие позволяет", id)
		}
	}
	for _, id := range []string{"slightly", "reduced", "unknown"} {
		if got := assigner.For(id); len(got) != 0 {
			t.Fatalf("%s пустили в слепую зону", id)
		}
	}
}

// Часть продавцов отдаёт не ссылки, а готовые конфиги ядра. Форма взята с живой
// подписки, значения выдуманы: класть в репозиторий чужие учётки нельзя
const xrayBody = `[
  {
    "remarks": "seller-1",
    "outbounds": [
      {
        "protocol": "vless",
        "settings": {
          "address": "sub.example.org", "port": 443, "flow": "xtls-rprx-vision",
          "id": "11111111-2222-3333-4444-555555555555", "encryption": "none"
        },
        "streamSettings": {
          "network": "tcp", "security": "reality",
          "realitySettings": {
            "fingerprint": "chrome", "publicKey": "pub-key", "shortId": "76ba",
            "serverName": "music.example.org", "spiderX": "/x", "mldsa65Verify": "pq-verify"
          }
        }
      },
      {"protocol": "freedom", "tag": "direct"}
    ]
  }
]`

func TestBuildsLinksFromWholeConfigs(t *testing.T) {
	links := ParseLinks([]byte(xrayBody))
	if len(links) != 1 {
		t.Fatalf("из конфига собрали %d ссылок", len(links))
	}
	link := links[0]
	for _, want := range []string{
		"vless://11111111-2222-3333-4444-555555555555@sub.example.org:443",
		"flow=xtls-rprx-vision", "security=reality", "pbk=pub-key", "sid=76ba",
		"sni=music.example.org", "fp=chrome",
		// Постквантовая подпись обязана доехать: без неё клиент не сойдётся с
		// сервером, который её требует
		"pqv=pq-verify",
	} {
		if !strings.Contains(link, want) {
			t.Fatalf("в ссылке нет %q: %s", want, link)
		}
	}
}

// Одна и та же подписка в двух форматах обязана дать одинаковые ссылки, иначе
// человек увидит разные серверы в зависимости от того, как продавец отдал тело
func TestConfigAndPlainFormatsAgree(t *testing.T) {
	fromConfig := ParseLinks([]byte(xrayBody))
	if len(fromConfig) != 1 {
		t.Fatal("конфиг не разобрался")
	}
	plain := base64.StdEncoding.EncodeToString([]byte(fromConfig[0]))
	fromPlain := ParseLinks([]byte(plain))
	if len(fromPlain) != 1 || fromPlain[0] != fromConfig[0] {
		t.Fatalf("форматы разъехались:\n%s\n%s", fromConfig[0], fromPlain[0])
	}
}

// Порядок параметров устойчив: иначе одна и та же подписка от чтения к чтению
// даёт разные строки, и человеку кажется, что сервер сменился
func TestLinkIsStableAcrossReads(t *testing.T) {
	first := ParseLinks([]byte(xrayBody))
	second := ParseLinks([]byte(xrayBody))
	if first[0] != second[0] {
		t.Fatal("одно и то же тело дало разные ссылки")
	}
}

// memStore - хранилище в памяти, чтобы проверить, что рубильник доезжает до
// базы, а не остаётся жить в одном процессе
type memStore struct {
	sources []Source
	on      bool
	saved   int
}

func (m *memStore) Load() ([]Source, error)     { return m.sources, nil }
func (m *memStore) Save(sources []Source) error { m.sources = sources; return nil }
func (m *memStore) LoadEnabled() (bool, error)  { return m.on, nil }
func (m *memStore) SaveEnabled(on bool) error   { m.on = on; m.saved++; return nil }

// Включённая раздача обязана пережить выкат: иначе владелец жмёт тумблер, а
// после первого же рестарта у людей опять пусто, и хер поймёшь почему
func TestEnableSurvivesRestart(t *testing.T) {
	store := &memStore{}
	pool := NewPool(store, nil)
	pool.Enable(true)
	if !store.on || store.saved != 1 {
		t.Fatalf("рубильник не записался: on=%v saved=%d", store.on, store.saved)
	}

	restarted := NewPool(store, nil)
	if err := restarted.Load(); err != nil {
		t.Fatalf("подъём обосрался: %v", err)
	}
	if !restarted.Enabled() {
		t.Fatal("после рестарта раздача снова выключена")
	}

	restarted.Enable(false)
	again := NewPool(store, nil)
	if err := again.Load(); err != nil {
		t.Fatalf("подъём обосрался: %v", err)
	}
	if again.Enabled() {
		t.Fatal("выключенная раздача воскресла")
	}
}
