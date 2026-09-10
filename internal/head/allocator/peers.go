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
