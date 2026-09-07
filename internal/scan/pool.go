package scan

import (
	"net"
	"sort"
	"strings"
)

// RussianPool is dests hosted in or served from Russia.
//
// They matter because a REALITY dest has to be traffic the user's network finds
// unremarkable. For a Russian user, a connection to a Yandex or Ozon endpoint is
// exactly that, where a connection to a Silicon Valley CDN is the thing being
// looked for. The node still dials the dest itself, so what matters is that the
// donated machine can reach it
// RussianPool is dests that look unremarkable to a Russian network.
//
// Часть из них физически стоит за границей, и это только на руку: SNI выглядит
// как обычный поход в отечественный сервис, а трафик при этом законно уходит из
// страны
//
// Most of these are taken from a public list of VLESS configs that is actually in
// service (github.com/zieng2/wl, the subscription the app ships as its default),
// so they are known to work in the field rather than merely to look plausible.
// A REALITY dest has to be traffic the user's network finds boring: for a Russian
// user a connection to Yandex or VK is exactly that, where a connection to a
// Silicon Valley CDN is the thing being looked for.
//
// The node dials the dest itself, so what matters is that the donated machine can
// reach it. Every entry here is scanned before use; nothing is trusted for being
// on the list
var RussianPool = []string{
	// The most used identities in that list, in order of how often they appear
	"api-maps.yandex.ru:443",
	"yandex.ru:443",
	"ya.ru:443",
	"max.ru:443",
	"web.max.ru:443",
	"ads.x5.ru:443",
	"5post-gate.x5.ru:443",
	"ads.vk.ru:443",
	"www.vk.com:443",
	"vk.ru:443",
	"eh.vk.com:443",
	"api.ok.ru:443",
	"360.yandex.ru:443",
	"sso.passport.yandex.ru:443",
	"smartcaptcha.yandexcloud.net:443",
	"strm.yandex.net:443",
	"optim.tildacdn.pub:443",
	"mapgasstation.ru:443",
	// Verified here, not taken from the list
	"music.yandex.ru:443",
	"market.yandex.ru:443",
	"translate.yandex.ru:443",
	"vkvideo.ru:443",
	"www.ozon.ru:443",
	"www.kinopoisk.ru:443",
	"auto.ru:443",
	"okko.tv:443",
	"tass.ru:443",
	"rambler.ru:443",
	"2gis.ru:443",
	"www.tbank.ru:443",
	"www.mvideo.ru:443",
	"cdn.ozone.ru:443",
	"www.avito.ru:443",
	"www.wildberries.ru:443",
	"static-basket-01.wbbasket.ru:443",
	"rutube.ru:443",
	"dzen.ru:443",
	"habr.com:443",
	"pikabu.ru:443",
	"hh.ru:443",
	"www.sports.ru:443",
}

// GlobalPool is the fallback set for a node with no route to a Russian endpoint.
//
// Здесь только то, куда из России ходят и так: обновления систем и телефонов,
// облачные сервисы. Компании, ушедшие с рынка, не годятся - запрос к ним с
// домашнего адреса сам по себе выделяется в трафике
var GlobalPool = []string{
	"dl.google.com:443",
	"www.microsoft.com:443",
	"www.samsung.com:443",
	"www.apple.com:443",
	"www.cloudflare.com:443",
	"aws.amazon.com:443",
}

// DefaultPool is what the head scans when an operator names nothing
func DefaultPool() []string {
	out := make([]string, 0, len(RussianPool)+len(GlobalPool))
	out = append(out, RussianPool...)
	out = append(out, GlobalPool...)
	return out
}

// ExpandSANs turns verified results into the wider set of names their
// certificates already cover.
//
// This is most of the value of scanning at all: the certificate on
// music.yandex.ru also covers the .uz, .kz and .by names, and each is a usable
// SNI that looks like an entirely different destination to anyone watching
func ExpandSANs(results []*Result) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		if r == nil || !r.Feasible {
			continue
		}
		for _, name := range r.ServerNames {
			if seen[name] || !PlausibleSNI(name) {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Best picks the dest to hand the fleet.
//
// Post-quantum capability outranks latency: it is a security property the whole
// fleet either has or does not, while a few tens of milliseconds on the borrowed
// handshake cost a user nothing
func Best(results []*Result) *Result {
	var best *Result
	for _, r := range results {
		if r == nil || !r.RealityOK {
			continue
		}
		if best == nil || better(r, best) {
			best = r
		}
	}
	return best
}

func better(a, b *Result) bool {
	if a.PostQuantumOK != b.PostQuantumOK {
		return a.PostQuantumOK
	}
	// h2 does not decide whether REALITY works, but a dest that speaks it is a
	// more convincing thing to be pretending to be
	if a.H2 != b.H2 {
		return a.H2
	}
	if a.LatencyMs != b.LatencyMs {
		return a.LatencyMs < b.LatencyMs
	}
	return a.Host < b.Host
}

// plausibleTLDs - зоны, куда российский пользователь ходит не удивляя никого.
// Глобальные плюс постсоветские: SNI это то, что видит цензор, и запрос к
// бразильскому домену с домашнего адреса в Твери сам по себе аномалия
var plausibleTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "dev": true,
	"app": true, "cloud": true, "ai": true, "me": true, "tv": true,
	"co": true, "info": true, "pro": true, "online": true, "site": true,
	"ru": true, "su": true, "by": true, "kz": true, "uz": true,
	"am": true, "ge": true, "kg": true, "tj": true, "md": true,
}

// PlausibleSNI reports whether a name is worth borrowing for Russian users.
//
// Сертификаты крупных компаний покрывают десятки региональных доменов сразу, и
// без фильтра в пул приезжают бразильские и индийские имена вместе с нужными
func PlausibleSNI(name string) bool {
	host := strings.TrimSpace(strings.ToLower(name))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	dot := strings.LastIndex(host, ".")
	if dot < 0 {
		return false
	}
	return plausibleTLDs[host[dot+1:]]
}
