package upstream

import (
	"net/url"
	"strings"
	"testing"
)

// Имя не должно содержать решётку: она едет во фрагменте ссылки, и всё, что
// читает фрагмент от последней решётки, показало бы человеку огрызок вместо
// имени сервера
func TestNameNeverCarriesAHash(t *testing.T) {
	source := Source{ID: "durev", Vendor: "Durev", Links: []string{
		"vless://x@host:443?type=ws#USA 66 [Белые списки]",
		"vless://y@host:443?type=ws",
	}}

	// Подпись продавца остаётся, наш вендор встаёт первым
	name := nameFor(source, 0)
	if name != "Durev USA 66 [Белые списки]" {
		t.Fatalf("имя не то: %q", name)
	}
	if strings.Contains(name, "#") {
		t.Fatalf("в имени решётка: %q", name)
	}
	raw := Rename(source.Links[0], name)
	fragment := raw[strings.LastIndex(raw, "#")+1:]
	if strings.ContainsAny(fragment, " \t") {
		t.Fatalf("в ссылке остался пробел, её обрежет любой парсер: %q", fragment)
	}
	decoded, err := url.PathUnescape(fragment)
	if err != nil {
		t.Fatalf("фрагмент не раскодировался: %v", err)
	}
	if decoded != name {
		t.Fatalf("после переименования фрагмент читается как %q", decoded)
	}

	// Продавец не подписал - зовём по вендору с номером
	if got := nameFor(source, 1); got != "Durev 2" {
		t.Fatalf("безымянный сервер назван %q", got)
	}
}
