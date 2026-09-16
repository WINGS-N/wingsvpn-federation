package allocator

import (
	"log"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Пиры VK TURN живут в релее ноды, и башка про них знает только из провижна.
// Без этой связки карантин отрезает учётку ядра, а туннель через релей
// продолжает работать

// Peers - откуда башка узнаёт про выданных пиров
type Peers interface {
	// KeysOf - ключи пиров человека на этой ноде
	KeysOf(clientID, nodeID string) ([]string, error)
	// AddressesOf - адреса пиров внутри туннеля. По ним ядро ноды и режет
	// скорость: у релея ограничителя нет
	AddressesOf(clientID, nodeID string) ([]string, error)
}

// SetPeers включает отзыв пиров вместе с профилем
func (a *Allocator) SetPeers(peers Peers) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.peers = peers
}

// peerKeys - что снимать с релея вместе с учёткой. Держит замок вызывающий
func (a *Allocator) peerKeys(userID, nodeID string) []string {
	if a.peers == nil {
		return nil
	}
	keys, err := a.peers.KeysOf(userID, nodeID)
	if err != nil {
		log.Printf("allocator: peer keys for %s on %s are unreadable: %v", userID, nodeID, err)
		return nil
	}
	return keys
}

// PeerLimitsFor - потолки для всех пиров, выданных на этой ноде.
//
// Нужны при каждом подключении агента, а не только при выдаче профиля: карта
// "адрес в туннеле - чей он" живёт у агента в памяти, и после его перезапуска
// наблюдения с релея вешать не на кого. Нода при этом возит трафик и молча
// выглядит ослепшей
func (a *Allocator) PeerLimitsFor(nodeID string) []*fedpb.PeerLimit {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*fedpb.PeerLimit
	for userID, alloc := range a.state {
		for key, p := range alloc.Profiles {
			if node, _ := splitKey(key); node != nodeID {
				continue
			}
			out = append(out, a.peerLimits(userID, nodeID, p.ID, p.DownlinkBps)...)
		}
	}
	return out
}

// peerLimits - какие потолки поставить пирам человека на этой ноде
func (a *Allocator) peerLimits(userID, nodeID, profileID string, downBps uint64) []*fedpb.PeerLimit {
	if a.peers == nil {
		return nil
	}
	addresses, err := a.peers.AddressesOf(userID, nodeID)
	if err != nil || len(addresses) == 0 {
		return nil
	}
	out := make([]*fedpb.PeerLimit, 0, len(addresses))
	for _, addr := range addresses {
		out = append(out, &fedpb.PeerLimit{
			AllowedIps: addr, DownlinkBps: downBps, ProfileId: profileID,
		})
	}
	return out
}
