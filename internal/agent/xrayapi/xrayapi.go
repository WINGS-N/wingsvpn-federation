// Package xrayapi talks to Xray's own gRPC on loopback.
//
// Reduced port of 3x-ui internal/xray/api.go: only QueryStats, the online
// queries and AlterInbound. A full port drags in every proxy protocol, and the
// core itself is deliberately not a Go dependency here - the agent ships to
// donated boxes and has no business carrying a copy of Xray inside it
package xrayapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	xraypb "wingsnet.org/federation/gen/xraypb"
)

// vlessAccountType is what Xray's TypedMessage registry resolves the account
// against. It is the proto full name and must match the core exactly
const vlessAccountType = "xray.proxy.vless.Account"

// Client is a lazily connected handle to one local Xray
type Client struct {
	addr string

	mu      sync.Mutex
	conn    *grpc.ClientConn
	stats   xraypb.StatsServiceClient
	handler xraypb.HandlerServiceClient
	watch   xraypb.WingsWatchClient
}

// New builds a client for an Xray listening on addr, without dialing yet: the
// core is often not up when the agent starts
func New(addr string) *Client { return &Client{addr: addr} }

// NewLocal builds a client for the loopback api inbound xraycfg renders
func NewLocal(port int) *Client { return New(fmt.Sprintf("127.0.0.1:%d", port)) }

func (c *Client) dial() (xraypb.StatsServiceClient, xraypb.HandlerServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.stats, c.handler, nil
	}
	conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	c.conn = conn
	c.stats = xraypb.NewStatsServiceClient(conn)
	c.handler = xraypb.NewHandlerServiceClient(conn)
	c.watch = xraypb.NewWingsWatchClient(conn)
	return c.stats, c.handler, nil
}

// Watch отдаёт наблюдателя за соединениями. Ядро молчит, пока никто не подписан
func (c *Client) Watch() (xraypb.WingsWatchClient, error) {
	if _, _, err := c.dial(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.watch, nil
}

// Close drops the connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.stats, c.handler, c.watch = nil, nil, nil, nil
	return err
}

// Counter is one direction pair
type Counter struct {
	Up   uint64
	Down uint64
}

// Traffic is a QueryStats answer split by what the counter names refer to
type Traffic struct {
	// Users is keyed by the Xray email tag, which for a federation profile is
	// f-<random8> and carries no identity
	Users    map[string]Counter
	Inbounds map[string]Counter
	Total    Counter
}

// QueryTraffic pulls every traffic counter out of the core.
//
// reset is false on the 1 Hz path: the head derives deltas from cumulative
// counters, so resetting here would make a dropped sample lose traffic instead
// of being harmless
func (c *Client) QueryTraffic(ctx context.Context, reset bool) (Traffic, error) {
	stats, _, err := c.dial()
	if err != nil {
		return Traffic{}, err
	}
	resp, err := stats.QueryStats(ctx, &xraypb.QueryStatsRequest{Pattern: "", Reset_: reset})
	if err != nil {
		return Traffic{}, err
	}
	out := Traffic{Users: map[string]Counter{}, Inbounds: map[string]Counter{}}
	for _, s := range resp.GetStat() {
		kind, name, dir, ok := parseStatName(s.GetName())
		if !ok || s.GetValue() < 0 {
			continue
		}
		value := uint64(s.GetValue())
		var target map[string]Counter
		switch kind {
		case "user":
			target = out.Users
		case "inbound":
			target = out.Inbounds
		default:
			continue
		}
		counter := target[name]
		if dir == "uplink" {
			counter.Up += value
		} else {
			counter.Down += value
		}
		target[name] = counter
		// Inbound counters would double count what the user counters already
		// hold, so only one side feeds the total
		if kind == "user" {
			if dir == "uplink" {
				out.Total.Up += value
			} else {
				out.Total.Down += value
			}
		}
	}
	return out, nil
}

// parseStatName splits a counter name of the form
// user>>>f-1a2b3c4d>>>traffic>>>uplink
func parseStatName(name string) (kind, id, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[2] != "traffic" {
		return "", "", "", false
	}
	if parts[3] != "uplink" && parts[3] != "downlink" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[3], true
}

// OnlineIPs lists the addresses currently using one profile. Profile sharing
// shows up here without the agent ever looking at a destination
func (c *Client) OnlineIPs(ctx context.Context, email string) (map[string]int64, error) {
	stats, _, err := c.dial()
	if err != nil {
		return nil, err
	}
	resp, err := stats.GetStatsOnlineIpList(ctx, &xraypb.GetStatsRequest{Name: email})
	if err != nil {
		return nil, err
	}
	return resp.GetIps(), nil
}

// OnlineUsers lists who is connected right now
func (c *Client) OnlineUsers(ctx context.Context) ([]string, error) {
	stats, _, err := c.dial()
	if err != nil {
		return nil, err
	}
	resp, err := stats.GetAllOnlineUsers(ctx, &xraypb.GetAllOnlineUsersRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetUsers(), nil
}

// ErrNoEmail guards the remove path: an empty email matches nothing on the core
// but reads like a wildcard, and a wildcard here would be catastrophic
var ErrNoEmail = errors.New("xrayapi: empty email")

// AddUser puts a client on a live inbound.
//
// Flow has to match the inbound: a vision account rejects a client sending an
// empty flow, so one profile is two entries, vision on tcp and empty on xhttp
func (c *Client) AddUser(ctx context.Context, tag, email, uuid, flow string, level uint32) error {
	if email == "" {
		return ErrNoEmail
	}
	_, handler, err := c.dial()
	if err != nil {
		return err
	}
	account, err := proto.Marshal(&xraypb.Account{Id: uuid, Flow: flow})
	if err != nil {
		return err
	}
	op, err := proto.Marshal(&xraypb.AddUserOperation{
		User: &xraypb.User{
			Email: email,
			// Уровень задаёт потолок скорости: ядро ограничивает по уровню
			// политики, а не по конкретному аккаунту
			Level:   level,
			Account: &xraypb.TypedMessage{Type: vlessAccountType, Value: account},
		},
	})
	if err != nil {
		return err
	}
	_, err = handler.AlterInbound(ctx, &xraypb.AlterInboundRequest{
		Tag: tag,
		Operation: &xraypb.TypedMessage{
			Type:  string((&xraypb.AddUserOperation{}).ProtoReflect().Descriptor().FullName()),
			Value: op,
		},
	})
	return err
}

// RemoveUser takes a client off a live inbound
func (c *Client) RemoveUser(ctx context.Context, tag, email string) error {
	if email == "" {
		return ErrNoEmail
	}
	_, handler, err := c.dial()
	if err != nil {
		return err
	}
	op, err := proto.Marshal(&xraypb.RemoveUserOperation{Email: email})
	if err != nil {
		return err
	}
	_, err = handler.AlterInbound(ctx, &xraypb.AlterInboundRequest{
		Tag: tag,
		Operation: &xraypb.TypedMessage{
			Type:  string((&xraypb.RemoveUserOperation{}).ProtoReflect().Descriptor().FullName()),
			Value: op,
		},
	})
	return err
}

// InboundUserCount is the sanity check that what the head asked for is what the
// core actually holds
func (c *Client) InboundUserCount(ctx context.Context, tag string) (int64, error) {
	_, handler, err := c.dial()
	if err != nil {
		return 0, err
	}
	resp, err := handler.GetInboundUsersCount(ctx, &xraypb.GetInboundUserRequest{Tag: tag})
	if err != nil {
		return 0, err
	}
	return resp.GetCount(), nil
}
