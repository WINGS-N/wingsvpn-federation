// Package xraycfg renders the head's NodeConfig into an Xray config.
//
// Written rather than ported: 3x-ui builds its config from database rows,
// balancers and node egress, which is the wrong shape entirely for a node that
// is told what to serve
package xraycfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Keys the agent generated locally. The private halves never leave the node
type Keys struct {
	RealityPrivateKey string
	Mldsa65Seed       string
}

// Profile is one user on one inbound
type Profile struct {
	ID    string
	UUID  string
	Email string
	// Flow must match the inbound: vision on tcp, empty on xhttp
	Flow       string
	InboundTag string
	// Metered marks a federation profile. Everything unmetered on this node is
	// the donor's own paying client on a vanilla app, and must never be watched,
	// scored or asked for anything
	Metered bool
	// Level - уровень политики, в который разложены потолки скорости профиля
	Level uint32
}

// APIPort is where Xray serves its own gRPC. Loopback only: it can add and
// remove users on a live server, so exposing it would hand anybody the fleet
const APIPort = 62789

// Xray warns that REALITY on a port other than 443 raises the odds of the DPI
// blocking the address, so the head should place at least one transport there.
// Kept as a warning rather than a refusal: a donated box may already have 443
// taken, and half a node still beats none
const preferredRealityPort = 443

// NonStandardRealityPorts lists inbounds that will draw that warning, so the
// head can weigh it when assigning ports
func NonStandardRealityPorts(cfg *fedpb.NodeConfig) []uint32 {
	var out []uint32
	for _, in := range cfg.GetInbounds() {
		if in.GetReality() && in.GetPort() != preferredRealityPort {
			out = append(out, in.GetPort())
		}
	}
	return out
}

var (
	// ErrNoInbounds means the head sent a config that serves nothing
	ErrNoInbounds = errors.New("xraycfg: config has no inbounds")
	// ErrNoRealityKey means reality was asked for without a local keypair
	ErrNoRealityKey = errors.New("xraycfg: reality inbound without a private key")
)

// Render turns a NodeConfig plus the node's local keys into config.json
func Render(cfg *fedpb.NodeConfig, keys Keys, profiles []Profile) ([]byte, error) {
	if cfg == nil || len(cfg.GetInbounds()) == 0 {
		return nil, ErrNoInbounds
	}
	inbounds := []map[string]any{apiInbound()}
	for _, spec := range cfg.GetInbounds() {
		in, err := renderInbound(spec, cfg.GetReality(), keys, profiles, cfg.GetSniff())
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, in)
	}
	doc := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"api":       map[string]any{"tag": "api", "services": []string{"HandlerService", "StatsService", "WingsWatchService"}},
		"stats":     map[string]any{},
		"policy":    policy(),
		"inbounds":  inbounds,
		"outbounds": outbounds(),
		"routing":   routing(cfg.GetRouting()),
	}
	return json.MarshalIndent(doc, "", "  ")
}

// apiInbound exposes Xray's own gRPC on loopback so the agent can add and remove
// users without restarting: a restart on a donated node drops every existing
// connection, which is not an acceptable price for onboarding one free user
func apiInbound() map[string]any {
	return map[string]any{
		"tag":      "api",
		"listen":   "127.0.0.1",
		"port":     APIPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
	}
}

// policy turns on the per-user counters QueryStats reads.
//
// statsUserOnline нужен отдельно: без него ядро не трекает адреса подключённых,
// и GetAllOnlineUsers всегда пуст - сколько бы людей ни сидело на ноде
func policy() map[string]any {
	levels := map[string]any{}
	for i, tier := range SpeedTiers {
		level := map[string]any{
			"statsUserUplink":   true,
			"statsUserDownlink": true,
			"statsUserOnline":   true,
		}
		if tier.UplinkBps > 0 {
			level["uplinkSpeed"] = tier.UplinkBps
		}
		if tier.DownlinkBps > 0 {
			level["downlinkSpeed"] = tier.DownlinkBps
		}
		levels[strconv.Itoa(i)] = level
	}
	return map[string]any{
		"levels": levels,
		"system": map[string]any{
			"statsInboundUplink":   true,
			"statsInboundDownlink": true,
		},
	}
}

// SpeedTier - потолок скорости по направлениям. Канал домашнего пользователя
// несимметричен, поэтому одной цифрой оба конца не описать
type SpeedTier struct {
	UplinkBps   uint64
	DownlinkBps uint64
}

// speedSteps - ступени, из которых собирается сетка уровней, байт в секунду
var speedSteps = []uint64{1 << 20, 2 << 20, 5 << 20, 10 << 20, 25 << 20, 50 << 20}

// SpeedTiers - сетка потолков. Ядро ограничивает по уровню политики, а уровни
// живут в конфиге и на лету не добавляются: произвольную скорость на профиль
// выдать нельзя. Поэтому сетка задана заранее всеми парами ступеней, а башка
// берёт ближайшую, которая не превышает запрошенное. Нулевая - без потолка
var SpeedTiers = buildSpeedTiers()

func buildSpeedTiers() []SpeedTier {
	tiers := []SpeedTier{{}}
	for _, up := range speedSteps {
		for _, down := range speedSteps {
			tiers = append(tiers, SpeedTier{UplinkBps: up, DownlinkBps: down})
		}
	}
	return tiers
}

// LevelFor - уровень политики под запрошенную пару потолков. Берётся самая
// щедрая ступень, которая не превышает ни одного из них: обещать больше, чем
// сказано, нельзя
func LevelFor(uplinkBps, downlinkBps uint64) uint32 {
	if uplinkBps == 0 && downlinkBps == 0 {
		return 0
	}
	best, bestLevel := SpeedTier{}, uint32(0)
	for i, tier := range SpeedTiers {
		if i == 0 {
			continue
		}
		if uplinkBps > 0 && tier.UplinkBps > uplinkBps {
			continue
		}
		if downlinkBps > 0 && tier.DownlinkBps > downlinkBps {
			continue
		}
		if tier.UplinkBps+tier.DownlinkBps > best.UplinkBps+best.DownlinkBps {
			best, bestLevel = tier, uint32(i)
		}
	}
	if bestLevel == 0 {
		// Просят меньше самой мелкой ступени: отдаём её, а не безлимит
		return 1
	}
	return bestLevel
}

// ReceiptDoorPort - куда ядро заворачивает расписки, которые клиент не смог
// довезти до панели сам. Порт живёт на петле и наружу не торчит
const ReceiptDoorPort = 8909

// ReceiptDoorHost - имя, по которому клиент просит эту дверь. Реального DNS у
// него нет и не нужно: имя разбирает ядро на ноде и уводит его к себе
const ReceiptDoorHost = "receipts.wingsv.internal"

func outbounds() []map[string]any {
	return []map[string]any{
		{"tag": "direct", "protocol": "freedom"},
		{"tag": "blocked", "protocol": "blackhole"},
		{
			"tag":      "receipts",
			"protocol": "freedom",
			"settings": map[string]any{"redirect": fmt.Sprintf("127.0.0.1:%d", ReceiptDoorPort)},
		},
	}
}

func renderInbound(spec *fedpb.InboundSpec, reality *fedpb.RealityIdentity, keys Keys, profiles []Profile, sniff *fedpb.SniffPolicy) (map[string]any, error) {
	clients := make([]map[string]any, 0, len(profiles))
	for _, p := range profiles {
		if p.InboundTag != spec.GetTag() {
			continue
		}
		clients = append(clients, map[string]any{
			"id":    p.UUID,
			"email": p.Email,
			"flow":  p.Flow,
			"level": p.Level,
		})
	}
	stream, err := streamSettings(spec, reality, keys)
	if err != nil {
		return nil, err
	}
	in := map[string]any{
		"tag":      spec.GetTag(),
		"listen":   listenOr(spec.GetListen()),
		"port":     spec.GetPort(),
		"protocol": protocolOr(spec.GetProtocol()),
		"settings": map[string]any{
			"clients":    clients,
			"decryption": decryptionOr(spec.GetDecryption()),
		},
		"streamSettings": stream,
	}
	if sniff.GetEnabled() {
		in["sniffing"] = map[string]any{
			"enabled":      true,
			"destOverride": sniff.GetDestOverride(),
		}
	}
	return in, nil
}

func streamSettings(spec *fedpb.InboundSpec, reality *fedpb.RealityIdentity, keys Keys) (map[string]any, error) {
	network := spec.GetNetwork()
	if network == "" {
		network = "tcp"
	}
	out := map[string]any{"network": network}
	// За прокси адрес клиента приезжает заголовком, а не из сокета. Без этого
	// Xray видел бы адрес самого прокси, и детект расшаренных профилей молча
	// перестал бы отличать одного человека от сорока
	if spec.GetAcceptProxyProtocol() {
		out["sockopt"] = map[string]any{"acceptProxyProtocol": true}
	}
	if network == "xhttp" {
		out["xhttpSettings"] = xhttpSettings(spec.GetXhttp())
	}
	if !spec.GetReality() {
		return out, nil
	}
	if keys.RealityPrivateKey == "" {
		return nil, ErrNoRealityKey
	}
	out["security"] = "reality"
	settings := map[string]any{
		"dest":        reality.GetDest(),
		"serverNames": reality.GetServerNames(),
		"privateKey":  keys.RealityPrivateKey,
		"shortIds":    reality.GetShortIds(),
	}
	if fp := reality.GetFingerprint(); fp != "" {
		settings["fingerprint"] = fp
	}
	if reality.GetXver() != 0 {
		settings["xver"] = reality.GetXver()
	}
	// Post-quantum authentication, only when the head asked for it. The signature
	// has to fit inside the TLS handshake REALITY borrows from dest, and many
	// dests are too small for it - so this is a fleet-wide decision made against a
	// measured dest, never something switched on just because a key exists
	if reality.GetPostQuantum() && keys.Mldsa65Seed != "" {
		settings["mldsa65Seed"] = keys.Mldsa65Seed
	}
	out["realitySettings"] = settings
	return out, nil
}

func xhttpSettings(spec *fedpb.XhttpSpec) map[string]any {
	out := map[string]any{
		"path": pathOr(spec.GetPath()),
		"mode": modeOr(spec.GetMode()),
	}
	if spec.GetHost() != "" {
		out["host"] = spec.GetHost()
	}
	if spec.GetScMaxEachPostBytes() != 0 {
		out["scMaxEachPostBytes"] = spec.GetScMaxEachPostBytes()
	}
	if spec.GetXPaddingBytes() != 0 {
		out["xPaddingBytes"] = fmt.Sprintf("100-%d", spec.GetXPaddingBytes())
	}
	return out
}

func routing(policy *fedpb.RoutingPolicy) map[string]any {
	rules := []map[string]any{
		{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
		// Дверь для расписок стоит выше блокировок: она живёт на петле, а петля
		// подпадает под geoip:private и иначе была бы закрыта своим же правилом
		{"type": "field", "domain": []string{"full:" + ReceiptDoorHost}, "outboundTag": "receipts"},
	}
	if policy.GetBlockPrivate() {
		rules = append(rules, map[string]any{
			"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "blocked",
		})
	}
	if policy.GetBlockBittorrent() {
		rules = append(rules, map[string]any{
			"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "blocked",
		})
	}
	if sites := policy.GetBlockedGeosite(); len(sites) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "domain": sites, "outboundTag": "blocked",
		})
	}
	if ports := policy.GetBlockedPorts(); len(ports) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "port": portList(ports), "outboundTag": "blocked",
		})
	}
	return map[string]any{"domainStrategy": "AsIs", "rules": rules}
}

func portList(ports []uint32) string {
	out := ""
	for i, p := range ports {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%d", p)
	}
	return out
}

func listenOr(v string) string {
	if v == "" {
		return "0.0.0.0"
	}
	return v
}

func protocolOr(v string) string {
	if v == "" {
		return "vless"
	}
	return v
}

func decryptionOr(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

func pathOr(v string) string {
	if v == "" {
		return "/"
	}
	return v
}

func modeOr(v string) string {
	if v == "" {
		return "auto"
	}
	return v
}
