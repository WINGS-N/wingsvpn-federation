package fedserver

import (
	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Трафик VK TURN приходит с ноды по ключу пира. Связка ключ-профиль есть только
// у башки: провижн выдавала она, агент про людей не знает и знать не должен

// PeerOwners говорит, чей это пир
type PeerOwners interface {
	// OwnerOf - профиль, которому выдан ключ. Пусто, если ключ не наш: на релее
	// живут и собственные клиенты донора, и считать их мы не вправе
	OwnerOf(publicKey string) (clientID string, ok bool)
}

// SetPeerOwners включает разбор трафика VK TURN по людям
func (s *Server) SetPeerOwners(owners PeerOwners) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerOwners = owners
}

// applyPeerUsage разносит дельты пиров по профилям
func (s *Server) applyPeerUsage(peers []*fedpb.PeerDeltaSample) {
	if len(peers) == 0 {
		return
	}
	s.mu.Lock()
	owners := s.peerOwners
	s.mu.Unlock()
	if owners == nil {
		return
	}
	for _, peer := range peers {
		clientID, ok := owners.OwnerOf(peer.GetPublicKey())
		if !ok {
			// Провижн этого ключа башка не выдавала: вешать его трафик не на
			// кого
			continue
		}
		s.usage.AddUsage(clientID, "vktp", peer.GetUpDeltaBytes(), peer.GetDownDeltaBytes())
	}
}
