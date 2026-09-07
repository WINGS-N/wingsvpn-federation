// Package vktpctl talks to the local vk-turn-proxy relay over its own management
// gRPC.
//
// State comes from the relay, not from watching the process: a supervisor that
// only knows whether a pid exists reports a node healthy while the relay is
// still starting, or wedged, and every client fails meanwhile
package vktpctl

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"

	controlpb "wingsnet.org/federation/gen/controlpb"
	"wingsnet.org/federation/internal/common/tokenaead"
)

// Client is a connection to the relay's management API
type Client struct {
	conn   *grpc.ClientConn
	relay  controlpb.RelayClient
	target string
}

// Dial connects to the relay on loopback.
//
// The derivation is not fixed here: an updated relay accepts SHA-512, an older
// one only SHA-256, and the agent does not get to choose which build a donor
// already has. ClientFor tries the new one and remembers if the relay is older
func Dial(target, token string) (*Client, error) {
	// Токен нужен дважды: им шифруется транспорт и им же релей авторизует
	// вызовы. Без метаданных каждый запрос отбивается как неаутентифицированный
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(tokenaead.ClientFor(token, target, tokenaead.Peers)),
		grpc.WithPerRPCCredentials(bearer{token: token}))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, relay: controlpb.NewRelayClient(conn), target: target}, nil
}

// Close releases the connection
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// State is what the agent needs to know about the relay
type State struct {
	Reachable      bool
	Ready          bool
	Version        string
	BootID         string
	PeerCount      uint32
	ActiveSessions uint64
	ListenEndpoint string
	// PublicIP - адрес, каким релея видит интернет. За NAT он не совпадает ни с
	// одним адресом на интерфейсах машины
	PublicIP    string
	WgInterface string
	AesNi       bool
	WrapCipher  string
	// Federation - релей заперт на своём WireGuard и увести трафик не может
	Federation bool
	Uptime     time.Duration
}

// Status asks the relay what it is doing. An unreachable relay is reported as
// not ready rather than as an error, because a supervisor has to distinguish
// "starting up" from "broken" and both are normal states to be in
func (c *Client) Status(ctx context.Context) State {
	st, err := c.relay.GetStatus(ctx, &controlpb.GetStatusRequest{})
	if err != nil {
		return State{}
	}
	return State{
		Reachable:      true,
		Ready:          st.GetReady(),
		Version:        st.GetVersion(),
		BootID:         st.GetBootId(),
		PeerCount:      st.GetPeerCount(),
		ActiveSessions: st.GetActiveSessions(),
		ListenEndpoint: st.GetListenEndpoint(),
		PublicIP:       st.GetPublicIp(),
		WgInterface:    st.GetWgInterface(),
		AesNi:          st.GetAesNi(),
		WrapCipher:     st.GetWrapCipher(),
		Federation:     st.GetFederation(),
		Uptime:         time.Duration(st.GetUptimeSeconds()) * time.Second,
	}
}

// ErrNotReachable means the relay did not answer
var ErrNotReachable = errors.New("vktpctl: relay is not answering")

// Flow is the relay's cumulative view, used to feed the head's own accounting
type Flow struct {
	ActiveStreams  uint32
	ActiveSessions uint32
	RxBytes        uint64
	TxBytes        uint64
}

// FlowStats returns the relay's cumulative counters
func (c *Client) FlowStats(ctx context.Context) (Flow, error) {
	stats, err := c.relay.GetFlowStats(ctx, &controlpb.GetFlowStatsRequest{})
	if err != nil {
		return Flow{}, ErrNotReachable
	}
	return Flow{
		ActiveStreams:  stats.GetActiveStreams(),
		ActiveSessions: stats.GetActiveSessions(),
		RxBytes:        stats.GetServerRxBytes(),
		TxBytes:        stats.GetServerTxBytes(),
	}, nil
}

// Reload asks the relay to re-read what it can without dropping traffic.
//
// It returns what still needs a restart rather than hiding it: the transport key
// is bound when the relay starts, and a caller that believes a reload covered it
// would report a change as applied while the relay kept serving the old one.
func (c *Client) Reload(ctx context.Context) (applied, restartRequired []string, err error) {
	resp, err := c.relay.Reload(ctx, &controlpb.ReloadRequest{})
	if err != nil {
		return nil, nil, err
	}
	return resp.GetApplied(), resp.GetRestartRequired(), nil
}

// Relisten переносит приём данных релея на другой адрес и возвращает тот, что
// получился.
//
// Прежний сокет доживает свои сессии drain, поэтому смена порта не рвёт тех, у
// кого в профиле ещё старый адрес. Занятый порт возвращается ошибкой, и релей
// при этом продолжает принимать там, где принимал
func (c *Client) Relisten(ctx context.Context, addr string, drain time.Duration) (string, error) {
	seconds := uint32(drain / time.Second)
	resp, err := c.relay.Reload(ctx, &controlpb.ReloadRequest{Listen: addr, DrainSeconds: seconds})
	if err != nil {
		return "", err
	}
	for _, item := range resp.GetRestartRequired() {
		// Релей старой сборки честно говорит, что переезд ему не по силам:
		// молча считать адрес применённым нельзя
		if item == "listen" {
			return "", fmt.Errorf("relay cannot move its listen address without a restart")
		}
	}
	return resp.GetListen(), nil
}

// Shutdown просит релей выйти. Перезапуском занимается systemd или kubelet:
// чужим процессом агент не распоряжается
func (c *Client) Shutdown(ctx context.Context, reason string) error {
	_, err := c.relay.Shutdown(ctx, &controlpb.ShutdownRequest{Reason: reason})
	return err
}

// bearer кладёт токен в метаданные каждого вызова. Транспорт уже зашифрован
// общим секретом, поэтому передавать его открытым текстом здесь безопасно
type bearer struct {
	token string
}

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

func (b bearer) RequireTransportSecurity() bool { return false }

// Peer - что релей знает про одного пира
type Peer struct {
	PublicKey  string
	AllowedIPs string
	RxBytes    uint64
	TxBytes    uint64
}

// Peers перечисляет пиров вместе с их счётчиками.
//
// Это единственный способ узнать, КТО именно возит трафик через релей: общий
// счётчик процесса складывает всех в одну кучу, включая собственных клиентов
// донора
func (c *Client) Peers(ctx context.Context) ([]Peer, error) {
	list, err := c.relay.ListPeers(ctx, &controlpb.ListPeersRequest{})
	if err != nil {
		return nil, ErrNotReachable
	}
	out := make([]Peer, 0, len(list.GetPeers()))
	for _, p := range list.GetPeers() {
		out = append(out, Peer{
			PublicKey: p.GetPublicKey(), AllowedIPs: p.GetAllowedIps(),
			RxBytes: p.GetRxBytes(), TxBytes: p.GetTxBytes(),
		})
	}
	return out, nil
}

// DropPeer выкидывает пира с релея.
//
// Без этого карантин у VK TURN был бумажным: новый провижн отбивался, а уже
// выданный пир продолжал возить трафик, потому что живёт он в релее, и голова
// его не трогала
func (c *Client) DropPeer(ctx context.Context, publicKey string) error {
	_, err := c.relay.DeletePeer(ctx, &controlpb.DeletePeerRequest{PublicKey: publicKey})
	return err
}
