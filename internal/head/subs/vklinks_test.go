package subs

import "testing"

// Пул звонков обязан ехать в самой подписке: провижн доходит не всегда, а без
// ссылок VK TURN у человека просто нет связи
func TestПулСсылокЕдетВПодписке(t *testing.T) {
	pool := []string{"https://vk.com/call/join/one", "https://vk.com/call/join/two"}
	cfg := Bundle(nil, []Turn{{
		ID: "turn-1", Name: "Federation", Endpoint: "1.2.3.4:443",
		Settings: TurnSettings{VKLinks: pool},
	}}, "Federation")

	got := cfg.GetTurn().GetProfiles()
	if len(got) != 1 {
		t.Fatalf("профилей %d, а должен быть один", len(got))
	}
	if links := got[0].GetConfig().GetLinks(); len(links) != len(pool) {
		t.Fatalf("в подписку уехало %d ссылок вместо %d", len(links), len(pool))
	}
}
