// Package subs serves subscriptions.
//
// The head owns this rather than the panel because the panel has no subscription
// machinery at all: it can tell a device to refresh, but the device fetches the
// body itself. Building that from scratch belongs next to the thing that knows
// which nodes a user has
package subs

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wingsnet.org/federation/deploy"
	"wingsnet.org/federation/internal/head/allocator"
	"wingsnet.org/federation/internal/head/devices"
)

// Label names the profiles a client sees
const Label = "WINGS-free"

// Path is where a subscription is fetched from
const Path = "/sub/"

// ContentType - тип тела подписки. Свой, а не text/plain: по нему приложение
// понимает, что перед ним кадр, а не список ссылок
const ContentType = "application/x-wingsv-config"

// refreshHint tells a client how often to come back. An hour: nodes rotate on a
// far slower clock than that, and a shorter interval only adds load
const refreshHint = "3600"

// Allocations is what the handler needs from the allocator
type Allocations interface {
	ByToken(token string) (*allocator.Allocation, bool)
	Ensure(userID string) (*allocator.Allocation, error)
	// EnsureDevice выдаёт устройству свои учётки на тех же нодах: лимит
	// устройств иначе бумажный, а пересланная ссылка неотличима от хозяйской
	EnsureDevice(userID, deviceID string) (*allocator.Allocation, error)
	Links(userID, deviceID, label string) ([]string, error)
	TurnProfiles(userID, deviceID string) []allocator.TurnProfile
	Usage(userID string) uint64
}

// Devices решает, этому ли устройству можно забирать подписку. Без него ссылка
// работает у любого, кому её переслали
type Devices interface {
	Admit(subjectID string, fp devices.Fingerprint) error
}

// Handler serves subscription bodies
type Handler struct {
	alloc   Allocations
	devices Devices
	// turnSettings - чем прикидываться и как обфусцировать. Оператор правит их
	// в панели, а не каждый человек у себя в телефоне
	turnSettings func() TurnSettings
	// silent зовётся, когда клиент не назвал устройство. Наше приложение шлёт
	// отпечаток всегда, поэтому молчание само по себе повод присмотреться
	silent func(subjectID string)
	// quota - месячный потолок человека. Съебывает в заголовок подписки, откуда
	// приложение рисует остаток: без него человек узнаёт про лимит ровно в тот
	// момент, когда в него ебанулся
	quota func(subjectID string) uint64
}

// SetQuota включает показ остатка трафика
func (h *Handler) SetQuota(fn func(subjectID string) uint64) { h.quota = fn }

// NewHandler builds a handler over an allocator
func NewHandler(alloc Allocations) *Handler { return &Handler{alloc: alloc} }

// SetTurnSettings задаёт, откуда брать настройки пути VK TURN
func (h *Handler) SetTurnSettings(fn func() TurnSettings) { h.turnSettings = fn }

// turnPath отдаёт текущие настройки пути
func (h *Handler) turnPath() TurnSettings {
	if h.turnSettings == nil {
		return TurnSettings{}
	}
	return h.turnSettings()
}

// SetDevices включает привязку подписки к устройствам
func (h *Handler) SetDevices(d Devices, onSilent func(string)) {
	h.devices, h.silent = d, onSilent
}

// InstallerPath is where a donated machine fetches the installer
const InstallerPath = "/fed/join.sh"

// Register mounts the subscription route
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle(Path, h)
}

// RegisterInstaller serves the installer with this head's own address baked in.
//
// It lives on the same listener as the subscription because both are the public
// HTTP face of the head, and because a donor pasting a command should not have to
// be told a second hostname
func RegisterInstaller(mux *http.ServeMux, head, release string) {
	script := deploy.JoinScript(head, release)
	mux.HandleFunc(InstallerPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte(script))
	})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, Path)
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	alloc, ok := h.alloc.ByToken(token)
	if !ok {
		// A bad token is not distinguished from a missing one: the difference
		// would tell somebody guessing that they had found a real user
		http.NotFound(w, r)
		return
	}

	// Refresh on fetch. The client asking is the only reliable signal that it is
	// still around, and a user whose node was parked gets a working config from
	// the same request that would otherwise have handed them a dead one
	// Устройство названо в том же заголовке, по которому его пускают к подписке,
	// и его же учётки уезжают в ответ
	deviceID := fingerprintOf(r).HWID
	if _, err := h.alloc.EnsureDevice(alloc.UserID, deviceID); err != nil {
		http.Error(w, "no capacity", http.StatusServiceUnavailable)
		return
	}
	links, err := h.alloc.Links(alloc.UserID, deviceID, Label)
	if err != nil || len(links) == 0 {
		http.Error(w, "no capacity", http.StatusServiceUnavailable)
		return
	}

	if wantsPage(r) {
		renderPage(w, PageData{
			URL:         subscriptionURL(r),
			Nodes:       len(alloc.NodeIDs()),
			StickyUntil: alloc.StickyUntil,
			UsedBytes:   h.alloc.Usage(alloc.UserID),
			LimitBytes:  h.quotaOf(alloc.UserID),
			Links:       append(linkViews(links), turnViews(turnsOf(h.alloc, alloc.UserID, deviceID, h.turnPath()))...),
		})
		return
	}

	// Устройство проверяется только на пути за конфигом. Страницу открывают
	// браузером, у которого отпечатка нет и быть не должно
	if h.devices != nil {
		err := h.devices.Admit(alloc.UserID, fingerprintOf(r))
		switch {
		case errors.Is(err, devices.ErrNoDevice):
			if h.silent != nil {
				h.silent(alloc.UserID)
			}
			http.Error(w, "client must identify its device", http.StatusForbidden)
			return
		case errors.Is(err, devices.ErrTooManyDevices):
			http.Error(w, "too many devices on this account", http.StatusForbidden)
			return
		case err != nil:
			http.Error(w, "device check failed", http.StatusServiceUnavailable)
			return
		}
	}

	// Тело подписки - тот же кадр, что в ссылке, но сырыми байтами: base64
	// добавил бы треть длины на ровном месте, а забирает его наше приложение
	body, err := EncodeConfigBytes(Bundle(links, turnsOf(h.alloc, alloc.UserID, deviceID, h.turnPath()), Label))
	if err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Profile-Update-Interval", refreshHint)
	w.Header().Set("Subscription-Userinfo", h.userinfo(alloc.UserID))
	// A subscription body is a bearer credential in itself, so no cache may keep
	// a copy of it
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Profile-Title", base64Title())
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

// quotaOf - месячный потолок человека, ноль означает, что потолка нет
func (h *Handler) quotaOf(userID string) uint64 {
	if h.quota == nil {
		return 0
	}
	return h.quota(userID)
}

// userinfo собирает строку остатка так, как её читают клиенты подписок.
//
// Весь расход идёт одним числом в download: башка считает трафик суммой, и
// раскладывать его обратно на приём с отдачей значило бы высасывать цифры из
// пальца
func (h *Handler) userinfo(userID string) string {
	used := h.alloc.Usage(userID)
	return fmt.Sprintf("upload=0; download=%d; total=%d", used, h.quotaOf(userID))
}

// base64Title is the encoded form clients expect for a non-ASCII-safe title
func base64Title() string {
	return "base64:" + base64.StdEncoding.EncodeToString([]byte(Label))
}

// Interval is the refresh cadence a caller can reuse when building a link
func Interval() time.Duration { return time.Hour }

// subscriptionURL восстанавливает адрес, по которому пришли: он же уходит в QR
func subscriptionURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	host := r.Host
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		host = forwarded
	}
	return scheme + "://" + host + r.URL.Path
}

// linkViews разбирает выданные ссылки на то, что показывают человеку: имя ноды
// и транспорт. Сама ссылка на страницу не попадает
func linkViews(links []string) []LinkView {
	out := make([]LinkView, 0, len(links))
	for _, link := range links {
		view := LinkView{Name: "сервер", Transport: "tcp"}
		if idx := strings.LastIndex(link, "#"); idx >= 0 && idx+1 < len(link) {
			view.Name = link[idx+1:]
			if decoded, err := url.QueryUnescape(view.Name); err == nil {
				view.Name = decoded
			}
		}
		if strings.Contains(link, "type=xhttp") || strings.Contains(link, "type=splithttp") {
			view.Transport = "xhttp"
		}
		out = append(out, view)
	}
	return out
}

// turnsOf переводит профили VK TURN в форму, которую понимает кодировщик
func turnsOf(alloc Allocations, userID, deviceID string, settings TurnSettings) []Turn {
	profiles := alloc.TurnProfiles(userID, deviceID)
	out := make([]Turn, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, Turn{
			ID: p.ID, Name: p.Name, Endpoint: p.Endpoint,
			ClientID: p.ClientID, Token: p.Token,
			Settings: settings,
		})
	}
	return out
}

// turnViews показывает VK TURN в том же списке серверов, что и Xray: для
// человека это один список, а не два протокола
func turnViews(turns []Turn) []LinkView {
	out := make([]LinkView, 0, len(turns))
	for _, t := range turns {
		out = append(out, LinkView{Name: t.Name, Transport: "vktp"})
	}
	return out
}

// fingerprintOf читает то, чем клиент себя назвал
func fingerprintOf(r *http.Request) devices.Fingerprint {
	return devices.Fingerprint{
		HWID:     r.Header.Get("x-hwid"),
		DeviceOS: r.Header.Get("x-device-os"),
		VerOS:    r.Header.Get("x-ver-os"),
		Model:    r.Header.Get("x-device-model"),
	}
}
