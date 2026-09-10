package subs

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Trust - уровень доверия аккаунта, если башка умеет его считать
type Trust struct {
	Band       string
	Confidence int
}

// PageData - что показывает страница подписки, открытая в браузере
type PageData struct {
	URL string
	// PanelBase - откуда берутся шрифты. Своей раздачи у башки нет, а лицо у
	// страницы должно быть то же самое, что у панели
	PanelBase   string
	QR          template.URL
	Links       []LinkView
	Nodes       int
	StickyUntil time.Time
	UsedBytes   uint64
	LimitBytes  uint64
	Trust       *Trust
}

// LinkView - одна ссылка в списке
type LinkView struct {
	Name      string
	Transport string
}

// wantsPage отличает браузер от клиента подписки: клиент забирает base64 и
// разбирает его сам, а человеку нужен QR и цифры
func wantsPage(r *http.Request) bool {
	switch r.URL.Query().Get("format") {
	case "raw", "config":
		return false
	case "page":
		return true
	}
	// Одного text/html в Accept мало: клиенты на HttpURLConnection подставляют
	// его сами и получали бы вёрстку вместо конфига. Браузер отличается тем,
	// что просит ещё и xhtml, а клиент подписки - тем, что называет себя
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, ContentType) {
		return false
	}
	if isSubscriptionClient(r.Header.Get("User-Agent")) {
		return false
	}
	return strings.Contains(accept, "application/xhtml+xml")
}

// subscriptionClients - те, кто ходит за подпиской, а не смотрит на неё
var subscriptionClients = []string{
	"wings", "v2ray", "xray", "clash", "sing-box", "nekoray", "nekobox",
	"shadowrocket", "surge", "quantumult", "stash", "hiddify", "streisand",
	"curl", "wget", "go-http-client", "okhttp", "java/",
}

func isSubscriptionClient(agent string) bool {
	agent = strings.ToLower(agent)
	if agent == "" {
		return true
	}
	for _, name := range subscriptionClients {
		if strings.Contains(agent, name) {
			return true
		}
	}
	return false
}

// panelBase - панель, чьи шрифты подтягивает страница
const panelBase = "https://v.wingsnet.org"

func renderPage(w http.ResponseWriter, data PageData) {
	if data.PanelBase == "" {
		data.PanelBase = panelBase
	}
	png, err := qrcode.Encode(data.URL, qrcode.Medium, 512)
	if err == nil {
		data.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, private")
	_, _ = w.Write(buf.Bytes())
}

// human переводит байты в то, что читается глазами
func human(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func bandLabel(band string) string {
	switch band {
	case "full":
		return "полный доступ"
	case "reduced":
		return "урезанный доступ"
	case "quarantine":
		return "карантин"
	default:
		return band
	}
}

func usedPct(used, limit uint64) int {
	if limit == 0 {
		return 0
	}
	pct := int(float64(used) / float64(limit) * 100)
	if pct > 100 {
		return 100
	}
	return pct
}

var pageTemplate = template.Must(template.New("sub").Funcs(template.FuncMap{
	"human": human,
	"band":  bandLabel,
	"pct":   usedPct,
	"date":  func(t time.Time) string { return t.Format("02.01.2006 15:04") },
}).Parse(pageHTML))
