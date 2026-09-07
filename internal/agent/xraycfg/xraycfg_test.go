package xraycfg

import (
	"encoding/json"
	"strings"
	"testing"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

func twoTransportConfig() *fedpb.NodeConfig {
	return &fedpb.NodeConfig{
		Version: 7,
		Reality: &fedpb.RealityIdentity{
			Dest:        "music.yandex.ru:443",
			ServerNames: []string{"music.yandex.ru"},
			ShortIds:    []string{"0123abcd"},
		},
		Inbounds: []*fedpb.InboundSpec{
			{Tag: "in-tcp", Network: "tcp", Port: 443, Flow: "xtls-rprx-vision", Reality: true},
			{Tag: "in-xhttp", Network: "xhttp", Port: 8443, Flow: "", Reality: true,
				Xhttp: &fedpb.XhttpSpec{Path: "/dl", Mode: "auto"}},
		},
		Sniff: &fedpb.SniffPolicy{Enabled: true, DestOverride: []string{"http", "tls"}},
	}
}

func render(t *testing.T, cfg *fedpb.NodeConfig, profiles []Profile) map[string]any {
	t.Helper()
	data, err := Render(cfg, Keys{RealityPrivateKey: "priv", Mldsa65Seed: "seed"}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("rendered config is not valid json: %v", err)
	}
	return doc
}

func inboundByTag(t *testing.T, doc map[string]any, tag string) map[string]any {
	t.Helper()
	for _, raw := range doc["inbounds"].([]any) {
		in := raw.(map[string]any)
		if in["tag"] == tag {
			return in
		}
	}
	t.Fatalf("inbound %q missing", tag)
	return nil
}

// Both transports must share one reality identity on different ports
func TestBothTransportsShareOneRealityIdentity(t *testing.T) {
	doc := render(t, twoTransportConfig(), nil)

	tcp := inboundByTag(t, doc, "in-tcp")["streamSettings"].(map[string]any)
	xhttp := inboundByTag(t, doc, "in-xhttp")["streamSettings"].(map[string]any)

	if tcp["network"] != "tcp" || xhttp["network"] != "xhttp" {
		t.Fatalf("networks = %v / %v", tcp["network"], xhttp["network"])
	}
	if tcp["security"] != "reality" || xhttp["security"] != "reality" {
		t.Fatal("reality is not enabled on both inbounds")
	}
	tcpReality := tcp["realitySettings"].(map[string]any)
	xhttpReality := xhttp["realitySettings"].(map[string]any)
	if tcpReality["privateKey"] != xhttpReality["privateKey"] {
		t.Error("the two inbounds ended up with different reality keys")
	}
	if tcpReality["dest"] != xhttpReality["dest"] {
		t.Error("the two inbounds ended up with different dests")
	}
	// Post-quantum auth must be present when the node generated a seed
	// Off unless the head asked: the signature has to fit inside the handshake
	// REALITY borrows from dest, and many dests are too small for it
	if _, present := tcpReality["mldsa65Seed"]; present {
		t.Error("post-quantum signing was enabled without the head asking")
	}
	if _, ok := xhttp["xhttpSettings"]; !ok {
		t.Error("xhttp inbound has no xhttpSettings")
	}
}

// VLESS rejects a connection whose account carries the vision flow when the
// client sent an empty one, so one profile needs a separate client entry per
// inbound and the flows must not be mixed up
func TestVisionFlowIsPerInbound(t *testing.T) {
	profiles := []Profile{
		{ID: "p1", UUID: "uuid-1", Email: "f-abc", Flow: "xtls-rprx-vision", InboundTag: "in-tcp"},
		{ID: "p1", UUID: "uuid-1", Email: "f-abc", Flow: "", InboundTag: "in-xhttp"},
	}
	doc := render(t, twoTransportConfig(), profiles)

	tcpClients := inboundByTag(t, doc, "in-tcp")["settings"].(map[string]any)["clients"].([]any)
	xhttpClients := inboundByTag(t, doc, "in-xhttp")["settings"].(map[string]any)["clients"].([]any)
	if len(tcpClients) != 1 || len(xhttpClients) != 1 {
		t.Fatalf("clients = %d tcp, %d xhttp", len(tcpClients), len(xhttpClients))
	}
	if got := tcpClients[0].(map[string]any)["flow"]; got != "xtls-rprx-vision" {
		t.Errorf("tcp flow = %v, want vision", got)
	}
	if got := xhttpClients[0].(map[string]any)["flow"]; got != "" {
		t.Errorf("xhttp flow = %v, want empty or VLESS refuses the connection", got)
	}
	// Same user, same uuid, two entries: that is the point
	if tcpClients[0].(map[string]any)["id"] != xhttpClients[0].(map[string]any)["id"] {
		t.Error("the same profile got different uuids on the two inbounds")
	}
}

// The api inbound is what lets the agent add users without a restart, and a
// restart would drop every existing connection on a donated node
func TestApiInboundIsLoopbackOnly(t *testing.T) {
	doc := render(t, twoTransportConfig(), nil)
	api := inboundByTag(t, doc, "api")
	if api["listen"] != "127.0.0.1" {
		t.Errorf("api listen = %v, want loopback: it can add users on a live server", api["listen"])
	}
	if _, ok := doc["stats"]; !ok {
		t.Error("stats block missing, QueryStats would return nothing")
	}
}

func TestPerUserCountersAreOn(t *testing.T) {
	doc := render(t, twoTransportConfig(), nil)
	levels := doc["policy"].(map[string]any)["levels"].(map[string]any)["0"].(map[string]any)
	// statsUserOnline включает трекинг подключённых, без него счётчик юзеров
	// на лендинге вечно показывает ноль
	if levels["statsUserOnline"] != true {
		t.Fatal("statsUserOnline выключен, онлайн-счётчик будет пустым")
	}
	if levels["statsUserUplink"] != true || levels["statsUserDownlink"] != true {
		t.Error("per-user counters are off, so per-profile traffic cannot be read")
	}
}

func TestRoutingBlocks(t *testing.T) {
	cfg := twoTransportConfig()
	cfg.Routing = &fedpb.RoutingPolicy{
		BlockBittorrent: true,
		BlockPrivate:    true,
		BlockedPorts:    []uint32{25, 465},
		BlockedGeosite:  []string{"geosite:category-ads-all"},
	}
	data, err := Render(cfg, Keys{RealityPrivateKey: "priv"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{"bittorrent", "geoip:private", "25,465", "category-ads-all"} {
		if !strings.Contains(body, want) {
			t.Errorf("routing is missing %q", want)
		}
	}
}

func TestRefusesRealityWithoutKey(t *testing.T) {
	if _, err := Render(twoTransportConfig(), Keys{}, nil); err != ErrNoRealityKey {
		t.Errorf("err = %v, want ErrNoRealityKey", err)
	}
}

func TestRefusesEmptyConfig(t *testing.T) {
	if _, err := Render(&fedpb.NodeConfig{}, Keys{RealityPrivateKey: "p"}, nil); err != ErrNoInbounds {
		t.Errorf("err = %v, want ErrNoInbounds", err)
	}
}

// Xray itself warns that REALITY away from 443 is likelier to get the address
// blocked, so the head needs to see which inbounds carry that risk
func TestNonStandardRealityPortsAreReported(t *testing.T) {
	cfg := twoTransportConfig()
	ports := NonStandardRealityPorts(cfg)
	if len(ports) != 1 || ports[0] != 8443 {
		t.Errorf("ports = %v, want just the xhttp inbound on 8443", ports)
	}
	// A node with everything on 443 has nothing to warn about
	cfg.Inbounds = []*fedpb.InboundSpec{{Tag: "in-tcp", Network: "tcp", Port: 443, Reality: true}}
	if got := NonStandardRealityPorts(cfg); len(got) != 0 {
		t.Errorf("ports = %v, want none", got)
	}
}

// The signature is only rendered when the head turned it on for the fleet
func TestPostQuantumIsRenderedOnlyWhenTheHeadAsks(t *testing.T) {
	cfg := twoTransportConfig()
	cfg.Reality.PostQuantum = true
	raw, err := Render(cfg, Keys{RealityPrivateKey: "priv", Mldsa65Seed: "seed"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, item := range doc["inbounds"].([]any) {
		in := item.(map[string]any)
		stream, ok := in["streamSettings"].(map[string]any)
		if !ok {
			continue
		}
		reality, ok := stream["realitySettings"].(map[string]any)
		if !ok {
			continue
		}
		if reality["mldsa65Seed"] != "seed" {
			t.Errorf("%v: seed missing once the head asked for it", in["tag"])
		}
	}
}

// Потолки скорости раскладываются в уровень политики: ядро ограничивает по
// уровню, а не по аккаунту
func TestLevelForPicksTheClosestTierBelow(t *testing.T) {
	if got := LevelFor(0, 0); got != 0 {
		t.Fatalf("без потолка уровень = %d, want 0", got)
	}

	level := LevelFor(5<<20, 10<<20)
	tier := SpeedTiers[level]
	if tier.UplinkBps != 5<<20 || tier.DownlinkBps != 10<<20 {
		t.Fatalf("точная пара не нашлась: %d/%d", tier.UplinkBps, tier.DownlinkBps)
	}

	// Запрошено между ступенями - берётся та, что не превышает
	between := SpeedTiers[LevelFor(7<<20, 30<<20)]
	if between.UplinkBps > 7<<20 || between.DownlinkBps > 30<<20 {
		t.Fatalf("ступень выше запрошенного: %d/%d", between.UplinkBps, between.DownlinkBps)
	}
	if between.UplinkBps != 5<<20 || between.DownlinkBps != 25<<20 {
		t.Fatalf("взята не ближайшая ступень: %d/%d", between.UplinkBps, between.DownlinkBps)
	}

	// Меньше самой мелкой ступени - всё равно потолок, а не безлимит
	if SpeedTiers[LevelFor(1024, 1024)].UplinkBps == 0 {
		t.Fatal("крошечный потолок превратился в безлимит")
	}
}

// В конфиге уровни несут раздельные потолки по направлениям
func TestPolicyLevelsCarrySeparateDirections(t *testing.T) {
	levels := policy()["levels"].(map[string]any)
	level := levels["1"].(map[string]any)
	if level["uplinkSpeed"] == nil || level["downlinkSpeed"] == nil {
		t.Fatal("уровень без потолков по направлениям")
	}
	if levels["0"].(map[string]any)["uplinkSpeed"] != nil {
		t.Fatal("нулевой уровень должен быть безлимитным")
	}
}
