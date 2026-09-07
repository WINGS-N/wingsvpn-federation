// Package profiles turns "this user gets this node" into what the node and the
// client each need: client entries for the core, and a share link for the app.
//
// Nothing here carries identity. A profile id is a random UUID and the Xray
// email tag is f-<random8>, because the node belongs to somebody else and a
// donor must never be able to read who is using it
package profiles

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
)

// Profile is one free user's access to one node
type Profile struct {
	ID     string
	UserID string
	NodeID string
	// UUID is the VLESS credential. Shared by both inbound entries: it is one
	// account, served over two transports
	UUID  string
	Email string
	// DeviceID - за каким устройством закреплена учётка. Пусто у выдач старого
	// образца и у клиентов, которые устройство не называют
	DeviceID string

	IssuedAt  time.Time
	ExpiresAt time.Time
	// UplinkBps и DownlinkBps - потолки скорости профиля, байт в секунду.
	// Соразмерны оценке Oracle, а не полосе. Ноль - без потолка
	UplinkBps   uint64
	DownlinkBps uint64
	// Usage - что прошло через профиль, по каждому транспорту отдельно. В списке
	// у человека это отдельные строки, и одна цифра на двоих врёт ему вдвое
	Usage map[string]TransportUsage
}

// TransportUsage - трафик одного транспорта профиля
type TransportUsage struct {
	UpBytes   uint64
	DownBytes uint64
	LastSeen  time.Time
}

// taggedEmail лепит тег учётки для конкретного инбаунда
func taggedEmail(email, inboundTag string) string {
	if email == "" || inboundTag == "" {
		return email
	}
	return email + "@" + inboundTag
}

// TransportOf достаёт транспорт из тега инбаунда: fed-tcp это tcp, fed-xhttp -
// xhttp. Человеку в списке показывается именно он
func TransportOf(inboundTag string) string {
	return strings.TrimPrefix(inboundTag, "fed-")
}

// ErrMissingIdentity means the node has not reported its REALITY public key, so
// no client could be pointed at it even if a profile were issued
var ErrMissingIdentity = errors.New("profiles: node has no reported reality identity")

// Issue mints a profile. The caller decides which node; this decides identity
func Issue(userID, nodeID string, now time.Time, ttl time.Duration) (Profile, error) {
	id, err := uuidV4()
	if err != nil {
		return Profile{}, err
	}
	credential, err := uuidV4()
	if err != nil {
		return Profile{}, err
	}
	tag, err := emailTag()
	if err != nil {
		return Profile{}, err
	}
	p := Profile{
		ID:       id,
		UserID:   userID,
		NodeID:   nodeID,
		UUID:     credential,
		Email:    tag,
		IssuedAt: now,
	}
	if ttl > 0 {
		p.ExpiresAt = now.Add(ttl)
	}
	return p, nil
}

// Specs is what goes down the wire to the node.
//
// One profile becomes two client entries on purpose: VLESS refuses a connection
// when the account carries the vision flow and the client sent an empty one, so
// the tcp inbound gets vision and the xhttp inbound gets none. Same UUID, same
// profile id, so removing the profile removes both
func (p Profile) Specs(cfg *fedpb.NodeConfig) []*fedpb.ProfileSpec {
	out := make([]*fedpb.ProfileSpec, 0, len(cfg.GetInbounds()))
	for _, in := range cfg.GetInbounds() {
		out = append(out, &fedpb.ProfileSpec{
			ProfileId: p.ID,
			Uuid:      p.UUID,
			// Тег свой на каждый инбаунд: ядро считает трафик именно по нему, и
			// с общим тегом оба транспорта слипаются в один счётчик, а человек
			// в приложении видит две строки и ждёт по цифре на каждую
			Email:      taggedEmail(p.Email, in.GetTag()),
			InboundTag: in.GetTag(),
			Flow:       in.GetFlow(),
			// Metered marks this as a federation profile. Everything else on the
			// node - the donor's own paying clients on vanilla clients - is not
			// metered, never asked for a receipt and never scored
			Metered:     true,
			UplinkBps:   p.UplinkBps,
			DownlinkBps: p.DownlinkBps,
		})
	}
	return out
}

// Links builds one share link per transport, in the form the rest of the stack
// already emits: security=reality with pbk, sid, fp, pqv and spx
func (p Profile) Links(node *registry.Node, cfg *fedpb.NodeConfig, label string) ([]string, error) {
	if node.RealityPublicKey == "" {
		return nil, ErrMissingIdentity
	}
	host := hostOf(node)
	if host == "" {
		return nil, fmt.Errorf("profiles: node %s has no reachable address", node.ID)
	}
	reality := cfg.GetReality()
	out := make([]string, 0, len(cfg.GetInbounds()))
	for _, in := range cfg.GetInbounds() {
		if !in.GetReality() {
			continue
		}
		params := url.Values{}
		params.Set("type", networkOf(in))
		params.Set("security", "reality")
		params.Set("encryption", "none")
		if names := reality.GetServerNames(); len(names) > 0 {
			params.Set("sni", names[0])
		}
		params.Set("pbk", node.RealityPublicKey)
		if ids := reality.GetShortIds(); len(ids) > 0 {
			params.Set("sid", ids[0])
		}
		params.Set("fp", fingerprint(reality))
		// Only when the fleet is actually serving it: a client that sends the
		// verify half to a node not signing with it fails to connect
		if reality.GetPostQuantum() && node.Mldsa65Verify != "" {
			params.Set("pqv", node.Mldsa65Verify)
		}
		params.Set("spx", "/")
		if flow := in.GetFlow(); flow != "" {
			params.Set("flow", flow)
		}
		if networkOf(in) == "xhttp" {
			params.Set("path", pathOf(in))
			params.Set("mode", modeOf(in))
		}
		// Порт из ссылки - тот, куда клиент стучится. За прокси он не совпадает с
		// тем, что слушает Xray, и подстановка слушающего дала бы ссылку,
		// ведущую в закрытый порт
		port := in.GetPort()
		if pub := in.GetPublicPort(); pub != 0 {
			port = pub
		}
		out = append(out, fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			p.UUID, host, port, params.Encode(),
			url.PathEscape(linkTitle(label, networkOf(in)))))
	}
	return out, nil
}

// linkTitle дописывает транспорт к имени сервера. Пустой label оставлен ради
// вызовов, которым имя не нужно: тогда работает старая форма с тегом инбаунда
func linkTitle(label, transport string) string {
	if strings.HasSuffix(label, " / ") {
		return label + strings.ToUpper(transport)
	}
	if label == "" {
		return strings.ToUpper(transport)
	}
	return label + " / " + strings.ToUpper(transport)
}

func fingerprint(reality *fedpb.RealityIdentity) string {
	if fp := reality.GetFingerprint(); fp != "" {
		return fp
	}
	return "chrome"
}

func networkOf(in *fedpb.InboundSpec) string {
	if n := in.GetNetwork(); n != "" {
		return n
	}
	return "tcp"
}

func pathOf(in *fedpb.InboundSpec) string {
	if p := in.GetXhttp().GetPath(); p != "" {
		return p
	}
	return "/"
}

func modeOf(in *fedpb.InboundSpec) string {
	if m := in.GetXhttp().GetMode(); m != "" {
		return m
	}
	return "auto"
}

// hostOf picks the address a client should dial. IPv4 only: a v6-only node is
// unreachable for almost every user, so a link naming one is a broken link
func hostOf(node *registry.Node) string {
	for _, addr := range node.Passport.GetAddresses() {
		if addr.GetIpv6() {
			continue
		}
		host := addr.GetAddress()
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			return host
		}
	}
	return ""
}

func uuidV4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return strings.Join([]string{h[:8], h[8:12], h[12:16], h[16:20], h[20:]}, "-"), nil
}

// emailTag is what the node sees a user as. Random on purpose: it is the label
// the donor's Xray logs and stats are keyed by
func emailTag() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "f-" + hex.EncodeToString(b), nil
}
