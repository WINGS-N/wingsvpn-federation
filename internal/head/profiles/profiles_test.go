package profiles

import (
	"net/url"
	"strings"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
)

func testConfig() *fedpb.NodeConfig {
	return &fedpb.NodeConfig{
		Version: 3,
		Reality: &fedpb.RealityIdentity{
			Dest:        "www.example.com:443",
			ServerNames: []string{"www.example.com"},
			ShortIds:    []string{"0123456789abcdef"},
		},
		Inbounds: []*fedpb.InboundSpec{
			{Tag: "fed-tcp", Network: "tcp", Port: 443, Flow: "xtls-rprx-vision", Reality: true},
			{Tag: "fed-xhttp", Network: "xhttp", Port: 8443, Reality: true,
				Xhttp: &fedpb.XhttpSpec{Path: "/dl", Mode: "auto"}},
		},
	}
}

func testNode() *registry.Node {
	return &registry.Node{
		ID:               "node-1",
		RealityPublicKey: "PBK-VALUE",
		Mldsa65Verify:    "PQV-VALUE",
		Passport: &fedpb.NodePassport{Addresses: []*fedpb.NodeAddress{
			{Address: "2001:db8::1", Ipv6: true},
			{Address: "203.0.113.7"},
		}},
	}
}

// The node belongs to somebody else, so nothing the user is may reach it
func TestIssuedProfileCarriesNoIdentity(t *testing.T) {
	p, err := Issue("user-alice@example.com", "node-1", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{p.ID, p.UUID, p.Email} {
		if strings.Contains(strings.ToLower(field), "alice") || strings.Contains(field, "@") {
			t.Errorf("field %q leaks who the user is", field)
		}
	}
	if !strings.HasPrefix(p.Email, "f-") || len(p.Email) != 10 {
		t.Errorf("email tag = %q, want f- plus 8 hex", p.Email)
	}
	if len(p.UUID) != 36 || p.UUID[14] != '4' {
		t.Errorf("uuid = %q, want a v4", p.UUID)
	}
}

func TestTwoProfilesNeverCollide(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := Issue("u", "n", time.Now(), 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{p.ID, p.UUID, p.Email} {
			if seen[v] {
				t.Fatalf("value repeated across profiles: %q", v)
			}
			seen[v] = true
		}
	}
}

// One account, two transports, two entries. VLESS refuses a client that sends an
// empty flow to a vision account, so sharing one entry across both inbounds
// silently breaks the xhttp half
func TestProfileBecomesOneEntryPerInboundWithMatchingFlow(t *testing.T) {
	p, err := Issue("u", "node-1", time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	specs := p.Specs(testConfig())
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want one per inbound", len(specs))
	}
	byTag := map[string]*fedpb.ProfileSpec{}
	for _, s := range specs {
		byTag[s.GetInboundTag()] = s
		if s.GetUuid() != p.UUID || s.GetProfileId() != p.ID {
			t.Error("the two entries are not the same account")
		}
		if !s.GetMetered() {
			t.Error("a federation profile must be metered")
		}
	}
	if got := byTag["fed-tcp"].GetFlow(); got != "xtls-rprx-vision" {
		t.Errorf("tcp flow = %q, want vision", got)
	}
	if got := byTag["fed-xhttp"].GetFlow(); got != "" {
		t.Errorf("xhttp flow = %q, want empty", got)
	}
}

func TestLinksCarryTheRealityParametersTheStackUses(t *testing.T) {
	p, err := Issue("u", "node-1", time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	links, err := p.Links(testNode(), testConfig(), "wings-free")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Fatalf("got %d links, want one per transport", len(links))
	}

	tcp, xhttp := links[0], links[1]
	// A v6-only address would be a broken link for almost every user
	if !strings.Contains(tcp, "@203.0.113.7:443") {
		t.Errorf("tcp link does not dial the v4 address: %s", tcp)
	}
	if !strings.Contains(xhttp, "@203.0.113.7:8443") {
		t.Errorf("xhttp link: %s", xhttp)
	}

	q := queryOf(t, tcp)
	for key, want := range map[string]string{
		"security": "reality",
		"pbk":      "PBK-VALUE",
		"sid":      "0123456789abcdef",
		"sni":      "www.example.com",
		"fp":       "chrome",
		"type":     "tcp",
		"flow":     "xtls-rprx-vision",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("tcp link %s = %q, want %q", key, got, want)
		}
	}

	if q.Get("pqv") != "" {
		t.Error("link carries a post-quantum verify half the node is not signing with")
	}

	qx := queryOf(t, xhttp)
	if qx.Get("flow") != "" {
		t.Errorf("xhttp link carries flow %q, which vision would reject", qx.Get("flow"))
	}
	if qx.Get("type") != "xhttp" || qx.Get("path") != "/dl" || qx.Get("mode") != "auto" {
		t.Errorf("xhttp params = %v", qx)
	}
}

// A node that never reported its public key cannot be pointed at, and saying so
// beats handing out a link that silently fails to connect
func TestLinksRefuseANodeWithNoIdentity(t *testing.T) {
	p, _ := Issue("u", "node-1", time.Now(), 0)
	n := testNode()
	n.RealityPublicKey = ""
	if _, err := p.Links(n, testConfig(), "x"); err == nil {
		t.Fatal("built a link for a node with no reality key")
	}
	n = testNode()
	n.Passport = &fedpb.NodePassport{Addresses: []*fedpb.NodeAddress{{Address: "2001:db8::1", Ipv6: true}}}
	if _, err := p.Links(n, testConfig(), "x"); err == nil {
		t.Fatal("built a link for a node with no v4 address")
	}
}

func queryOf(t *testing.T, link string) url.Values {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse %q: %v", link, err)
	}
	return u.Query()
}

// A client that sends the verify half to a node not signing with it fails to
// connect, so the link only carries it when the fleet is actually using it
func TestLinkCarriesPqvOnlyWhenTheFleetSignsWithIt(t *testing.T) {
	p, _ := Issue("u", "node-1", time.Now(), 0)
	cfg := testConfig()
	cfg.Reality.PostQuantum = true
	links, err := p.Links(testNode(), cfg, "x")
	if err != nil {
		t.Fatal(err)
	}
	if got := queryOf(t, links[0]).Get("pqv"); got != "PQV-VALUE" {
		t.Errorf("pqv = %q once the fleet signs, want the verify half", got)
	}
}

// За прокси Xray слушает свой локальный порт, а клиент стучится в порт прокси.
// Ссылка должна нести второй: с первым она ведёт в порт, закрытый снаружи.
func TestLinkCarriesThePublicPortWhenBehindAProxy(t *testing.T) {
	node := &registry.Node{
		ID:               "n1",
		RealityPublicKey: "pub",
		Passport:         &fedpb.NodePassport{Addresses: []*fedpb.NodeAddress{{Address: "203.0.113.7"}}},
	}
	cfg := &fedpb.NodeConfig{
		Reality: &fedpb.RealityIdentity{ServerNames: []string{"example.com"}, ShortIds: []string{"ab"}},
		Inbounds: []*fedpb.InboundSpec{
			{Tag: "fed-tcp", Network: "tcp", Port: 8443, PublicPort: 443, Reality: true},
		},
	}
	links, err := Profile{ID: "p", UUID: "uuid", NodeID: "n1"}.Links(node, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 {
		t.Fatalf("ссылок %d", len(links))
	}
	if !strings.Contains(links[0], ":443?") {
		t.Errorf("в ссылке не порт прокси: %s", links[0])
	}
	if strings.Contains(links[0], ":8443?") {
		t.Errorf("в ссылку попал слушающий порт: %s", links[0])
	}
}
