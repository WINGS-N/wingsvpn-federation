package provision

import (
	"context"
	"testing"

	provisioningpb "wingsnet.org/federation/gen/provisioningpb"
)

// Токен ходит по всему пути одним видом - hex-строкой: она в профиле подписки,
// она же в строковом поле приложения, она же приезжает в провижн
func TestMatchesTakesTheHexTokenTheAppCarries(t *testing.T) {
	const secret, clientID = "fleet-secret", "6cb403d9-cfb6-4bfc-99f8-2d3d814e1bdc"
	if !Matches(secret, clientID, []byte(TokenHex(secret, clientID))) {
		t.Fatal("hex-строка, ровно та что уходит в профиль подписки, отбита")
	}
	// Сырой дайджест по этому пути не ходит: в профиле лежит его hex, и
	// приложение везёт строку
	if Matches(secret, clientID, TokenFor(secret, clientID)) {
		t.Fatal("принят вид, которого в контракте нет")
	}
	if Matches(secret, clientID, []byte("deadbeef")) {
		t.Fatal("чужой токен принят")
	}
	if Matches(secret, clientID, []byte(TokenHex(secret, "another-client"))) {
		t.Fatal("токен другого клиента принят")
	}
	if Matches("another-secret", clientID, []byte(TokenHex(secret, clientID))) {
		t.Fatal("токен от чужого секрета принят")
	}
}

type rememberedPeer struct {
	clientID, nodeID, publicKey, allowedIPs string
}

type peerRecorder struct{ last rememberedPeer }

func (r *peerRecorder) Remember(clientID, nodeID, publicKey, allowedIPs string) error {
	r.last = rememberedPeer{clientID, nodeID, publicKey, allowedIPs}
	return nil
}

type okProfiles struct{}

func (okProfiles) VerifyProvision(string, []byte, string) bool { return true }

// Второй заход релея обязан вернуть весь конфиг: релей отдаёт приложению именно
// его, и пустой ответ доезжает до телефона туннелем без ключей
func TestReportPassReturnsTheWholeConfig(t *testing.T) {
	peers := &peerRecorder{}
	s := New(okProfiles{})
	s.SetPeers(peers)
	resp, err := s.ResolveClientConfig(context.Background(), &provisioningpb.ResolveClientConfigRequest{
		ClientId:          "client-1",
		NodeId:            "node-1",
		WgPublicKey:       "client-public",
		WgPrivateKey:      "client-private",
		WgAllowedIps:      "10.67.66.7/32",
		WgServerPublicKey: "node-public",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	wg := resp.GetWg()
	if wg == nil {
		t.Fatal("конфига в ответе нет вовсе")
	}
	if wg.GetPrivateKey() != "client-private" || wg.GetServerPublicKey() != "node-public" {
		t.Fatalf("ключи потерялись: %#v", wg)
	}
	if wg.GetAddress() != "10.67.66.7/32" {
		t.Fatalf("адрес интерфейса %q, а нода выдала 10.67.66.7/32", wg.GetAddress())
	}
	if wg.GetAllowedIps() != clientAllowedIPs || wg.GetMtu() != clientMTU {
		t.Fatalf("маршрут и mtu не проставлены: %#v", wg)
	}
	if resp.GetProvisionLocally() {
		t.Fatal("второй заход снова просит минтить пир")
	}
	if peers.last.publicKey != "client-public" || peers.last.allowedIPs != "10.67.66.7/32" {
		t.Fatalf("пир записан не тот: %#v", peers.last)
	}
}

// Первый заход - только команда минтить, никакого конфига там ещё нет
func TestFirstPassAsksTheNodeToMint(t *testing.T) {
	s := New(okProfiles{})
	resp, err := s.ResolveClientConfig(context.Background(), &provisioningpb.ResolveClientConfigRequest{
		ClientId: "client-1",
		NodeId:   "node-1",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !resp.GetProvisionLocally() {
		t.Fatal("нода не получила команду минтить пир")
	}
	if resp.GetWg() != nil {
		t.Fatal("конфиг обещан до того, как пир существует")
	}
}
