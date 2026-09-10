// Package provision отвечает релею на ноде, кому выдавать wg-пир.
//
// Контракт тот же, каким релей ходит в панель: у ноды федерации панели нет, и
// без этого сервиса VK TURN на ней обслуживать некого
package provision

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	provisioningpb "wingsnet.org/federation/gen/provisioningpb"
)

// Profiles - то, что сервису нужно от аллокатора: подтвердить, что такой
// профиль правда выдан этой ноде
type Profiles interface {
	VerifyProvision(clientID string, token []byte, nodeID string) bool
}

// Peers запоминает, какой wg-ключ достался какому профилю.
//
// Без этого весь трафик VK TURN висит на голом stream_id, за которым не стоит
// нихуя: посчитать его некому, сверить с распиской нечем, и обвинить в случае
// чего тоже некого
type Peers interface {
	Remember(clientID, nodeID, publicKey, allowedIPs string) error
}

const (
	// clientAllowedIPs - что телефон заворачивает в туннель. Федерация выдаёт
	// доступ целиком, а не сплит
	clientAllowedIPs = "0.0.0.0/0"

	// clientMTU - с запасом под DTLS поверх TURN: заголовки WRAP, DTLS и STUN
	// съедают заметно больше обычного WireGuard, и пакет впритык фрагментируется
	clientMTU = 1280
)

// Links отдаёт пул VK-ссылок на весь флот
type Links interface {
	VKLinks() []string
}

// Server реализует сервис провижна
type Server struct {
	provisioningpb.UnimplementedProvisioningServer

	profiles Profiles
	peers    Peers
	links    Links
}

// New строит сервис поверх аллокатора
func New(profiles Profiles) *Server { return &Server{profiles: profiles} }

// SetPeers включает запоминание выданных пиров
func (s *Server) SetPeers(p Peers) { s.peers = p }

// SetLinks включает раздачу пула VK-ссылок вместе с конфигом
func (s *Server) SetLinks(l Links) { s.links = l }

// vkLinks - пул на этот ответ. Пустой список законен: пока оператор не завёл
// ссылки, приложение живёт на той единственной, что приехала с QR
func (s *Server) vkLinks() []string {
	if s.links == nil {
		return nil
	}
	return s.links.VKLinks()
}

// ResolveClientConfig подтверждает клиента и велит ноде выпустить пир самой.
//
// Башка не держит wg-ключей: они рождаются и живут на ноде, а сюда приезжает
// только публичная половина. Обратный путь, когда сервер дозванивается до ноды,
// для федерации не годится: чужая машина за NAT принимает соединения, а не
// раздаёт их
func (s *Server) ResolveClientConfig(
	_ context.Context,
	req *provisioningpb.ResolveClientConfigRequest,
) (*provisioningpb.ResolveClientConfigResponse, error) {
	clientID := strings.TrimSpace(req.GetClientId())
	if clientID == "" {
		return nil, status.Error(codes.InvalidArgument, "missing client id")
	}
	// node_id релей не знает: идентификатор ноды живёт у агента, а не у него.
	// Пустое значение означает проверку только по клиенту и его токену
	if !s.profiles.VerifyProvision(clientID, req.GetToken(), req.GetNodeId()) {
		// Неизвестный клиент и неверный токен отвечают одинаково: разница
		// подсказала бы перебирающему, какой идентификатор существует
		return nil, status.Error(codes.PermissionDenied, "rejected")
	}
	// Второй заход, уже с выпущенным пиром. Релей зовёт эту же ручку повторно,
	// чтобы отчитаться о том, что наминтил, и вот тут связка наконец есть.
	//
	// Ответ обязан нести весь конфиг: релей отдаёт приложению именно его, а не
	// то, что наминтил сам. Пустой ответ доезжал до телефона конфигом без ключей,
	// и рантайм падал на "WireGuard keys missing"
	if key := strings.TrimSpace(req.GetWgPublicKey()); key != "" {
		if s.peers != nil {
			if err := s.peers.Remember(clientID, req.GetNodeId(), key, req.GetWgAllowedIps()); err != nil {
				log.Printf("provision: peer of %s not remembered: %v", clientID, err)
			}
		}
		return &provisioningpb.ResolveClientConfigResponse{
			VkLinks: s.vkLinks(),
			Wg: &provisioningpb.WireguardConfig{
				PrivateKey: req.GetWgPrivateKey(),
				PublicKey:  key,
				// Адрес интерфейса на телефоне - это то, что нода прописала пиру
				// в allowed-ips: там ровно один адрес этого клиента
				Address:         req.GetWgAllowedIps(),
				ServerPublicKey: req.GetWgServerPublicKey(),
				// А это уже маршрут на стороне телефона: в туннель уходит всё
				AllowedIps: clientAllowedIPs,
				Mtu:        clientMTU,
			},
		}, nil
	}
	return &provisioningpb.ResolveClientConfigResponse{ProvisionLocally: true, VkLinks: s.vkLinks()}, nil
}

// GetClientUsage - лимиты по клиентам этой ноды. Федерация считает трафик у
// себя, поэтому релею отдавать нечего
func (s *Server) GetClientUsage(
	_ context.Context,
	_ *provisioningpb.GetClientUsageRequest,
) (*provisioningpb.GetClientUsageResponse, error) {
	return &provisioningpb.GetClientUsageResponse{}, nil
}

// TokenFor выводит токен провижна из секрета профиля. Считается, а не хранится:
// отдельная таблица тут ничего не добавляет, а потерять её можно
func TokenFor(secret, clientID string) []byte {
	sum := sha512.Sum512_256([]byte(secret + "\x00" + clientID))
	return sum[:]
}

// TokenHex - тот же токен строкой, как его кладут в профиль приложения
func TokenHex(secret, clientID string) string {
	return hex.EncodeToString(TokenFor(secret, clientID))
}

// TokenMatches сравнивает токены за постоянное время
func TokenMatches(expected, got []byte) bool {
	return subtle.ConstantTimeCompare(expected, got) == 1
}

// Matches подтверждает токен клиента.
//
// Вид один и тот же на всём пути: hex-строка. Она кладётся в профиль подписки,
// хранится в приложении строковым полем и приезжает сюда её же байтами, так что
// сравнивать надо именно с TokenHex. Сырой дайджест тут не появляется ниоткуда,
// и принимать его значило бы держать вторую дверь ради никого
func Matches(secret, clientID string, got []byte) bool {
	return TokenMatches([]byte(TokenHex(secret, clientID)), got)
}
