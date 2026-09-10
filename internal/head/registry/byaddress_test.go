package registry

import (
	"testing"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Клиент подписывает расписку тем адресом, который набирает - с портом, - а
// паспорт несёт голый ip. Сверка строка-в-строку отбивала каждую расписку как
// названную на чужую ноду
func TestNodeByAddressIgnoresThePort(t *testing.T) {
	r := New()
	r.nodes["node-1"] = &Node{
		ID: "node-1",
		Passport: &fedpb.NodePassport{
			Addresses: []*fedpb.NodeAddress{{Address: "45.13.237.113"}},
		},
	}

	for _, claimed := range []string{"45.13.237.113:20463", "45.13.237.113", " 45.13.237.113:443 "} {
		got, ok := r.NodeByAddress(claimed)
		if !ok || got != "node-1" {
			t.Fatalf("адрес %q не привязался к ноде: %q %v", claimed, got, ok)
		}
	}
	if _, ok := r.NodeByAddress("1.2.3.4:20463"); ok {
		t.Fatal("чужой адрес привязался к нашей ноде")
	}
	if _, ok := r.NodeByAddress(""); ok {
		t.Fatal("пустой адрес привязался к ноде")
	}
}

// Адрес релея нода сообщает сама, и по нему её набирает приложение: паспорт при
// этом может ещё не доехать
func TestNodeByAddressFindsTheRelayEndpoint(t *testing.T) {
	r := New()
	r.nodes["node-2"] = &Node{ID: "node-2", RelayEndpoint: "45.137.70.68:38451"}
	got, ok := r.NodeByAddress("45.137.70.68:38451")
	if !ok || got != "node-2" {
		t.Fatalf("релейный адрес не привязался: %q %v", got, ok)
	}
}

func TestHostOfHandlesIPv6(t *testing.T) {
	if got := hostOf("[2a0e:97c0:711:33::1]:443"); got != "2a0e:97c0:711:33::1" {
		t.Fatalf("hostOf вернул %q", got)
	}
	if got := hostOf("2a0e:97c0:711:33::1"); got != "2a0e:97c0:711:33::1" {
		t.Fatalf("голый ipv6 покорёжен: %q", got)
	}
}
