package allocator

import "testing"

type fakePeers struct {
	keys  map[string][]string
	addrs map[string][]string
}

func (f fakePeers) KeysOf(clientID, nodeID string) ([]string, error) {
	return f.keys[clientID+"|"+nodeID], nil
}

func (f fakePeers) AddressesOf(clientID, nodeID string) ([]string, error) {
	return f.addrs[clientID+"|"+nodeID], nil
}

// Карантин обязан снимать и пира релея. Учётка ядра без этого отрезана, а
// туннель VK TURN продолжает работать по уже выданному ключу - то есть человек,
// которого мы "отрезали", спокойно ходит дальше
func TestRevokeDropsTheRelayPeerToo(t *testing.T) {
	a, _, push := setup(t, node("n1", 1), node("n2", 2))
	alloc, err := a.Ensure("user-1")
	if err != nil {
		t.Fatalf("выдача обосралась: %v", err)
	}
	var nodeID string
	for key := range alloc.Profiles {
		nodeID, _ = splitKey(key)
		break
	}
	a.SetPeers(fakePeers{keys: map[string][]string{
		"user-1|" + nodeID: {"wgkey-1"},
	}})

	a.Revoke("user-1")

	var dropped bool
	for _, key := range push.peers {
		if key == "wgkey-1" {
			dropped = true
		}
	}
	if !dropped {
		t.Fatalf("пир релея остался жив: сняли %v", push.peers)
	}
}

// Без источника ключей ничего не ломается: снимается учётка, как и раньше
func TestRevokeWorksWithoutPeers(t *testing.T) {
	a, _, push := setup(t, node("n1", 1))
	if _, err := a.Ensure("user-1"); err != nil {
		t.Fatalf("выдача обосралась: %v", err)
	}
	a.Revoke("user-1")
	if len(push.calls) == 0 {
		t.Fatal("профиль не сняли вовсе")
	}
}
