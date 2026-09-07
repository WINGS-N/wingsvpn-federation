package subs

import "testing"

func TestLinkNameFromFragment(t *testing.T) {
	link := "vless://id@1.2.3.4:443?type=tcp#%F0%9F%87%A9%F0%9F%87%AA%20Germany%20%231%20%2F%20TCP"
	if got := linkName(link, "fallback"); got != "🇩🇪 Germany #1 / TCP" {
		t.Fatalf("linkName = %q", got)
	}
	if got := linkName("vless://id@1.2.3.4:443", "fallback"); got != "fallback" {
		t.Fatalf("fallback = %q", got)
	}
}

// CONFIG_TYPE_ALL приложение принимает за полный бэкап и применяет настройки
// целиком, а списки профилей при этом теряет
func TestBundleStaysAProfileList(t *testing.T) {
	cfg := Bundle(
		[]string{"vless://uuid@1.2.3.4:443?type=tcp#node"},
		[]Turn{{ID: "t1", Name: "node / VKTP", Endpoint: "1.2.3.4:56000", ClientID: "c", Token: "k"}},
		"Federation",
	)
	if got := cfg.GetType().String(); got != "CONFIG_TYPE_XRAY" {
		t.Fatalf("type = %s, want CONFIG_TYPE_XRAY", got)
	}
	if len(cfg.GetTurn().GetProfiles()) != 1 || len(cfg.GetXray().GetProfiles()) != 1 {
		t.Fatalf("оба протокола должны доехать: turn=%d xray=%d",
			len(cfg.GetTurn().GetProfiles()), len(cfg.GetXray().GetProfiles()))
	}
}

// Идентификатор считается от ссылки, а не от места в списке. Иначе купленный
// сервер, вставший первым, забирает чужой номер, приложение склеивает два
// разных сервера в один и человек тыкает в строку, которая ему не принадлежит
func TestProfileIDFollowsTheLinkNotThePosition(t *testing.T) {
	first := "vless://uuid-1@a.example:443?type=tcp#Germany 1"
	second := "vless://uuid-2@b.example:443?type=ws#Durev Spain 2"

	before := XrayBundle([]string{first, second}, "WINGS-free")
	after := XrayBundle([]string{second, first}, "WINGS-free")

	if before.GetXray().GetProfiles()[0].GetId() != after.GetXray().GetProfiles()[1].GetId() {
		t.Fatal("id уехал вместе с местом в списке")
	}
	if before.GetXray().GetProfiles()[0].GetId() == before.GetXray().GetProfiles()[1].GetId() {
		t.Fatal("два разных сервера получили один id")
	}

	// Продавец переименовал сервер - это тот же сервер, id меняться не должен
	renamed := XrayBundle([]string{second + " renamed"}, "WINGS-free")
	plain := XrayBundle([]string{second}, "WINGS-free")
	if renamed.GetXray().GetProfiles()[0].GetId() != plain.GetXray().GetProfiles()[0].GetId() {
		t.Fatal("переименование сервера завело новый профиль")
	}
}
