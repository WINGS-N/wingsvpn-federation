package fedserver

import (
	"testing"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
)

func baseConfig() *fedpb.NodeConfig {
	return &fedpb.NodeConfig{
		Version: 7,
		Inbounds: []*fedpb.InboundSpec{
			{Tag: "fed-tcp", Network: "tcp", Port: 443, Reality: true},
			{Tag: "fed-xhttp", Network: "xhttp", Port: 8443, Reality: true},
		},
	}
}

// A host that could not take 443 must be served, and linked to, on the port it
// actually offered - otherwise it enrols happily and hands out dead links.
func TestConfigForUsesTheNodesOwnPorts(t *testing.T) {
	reg := registry.New()
	reg.Add(&registry.Node{ID: "busy", OfferedPorts: []uint32{2053, 2083}})
	reg.Add(&registry.Node{ID: "plain"})

	s := New(reg, nil, "head:443")
	s.SetNodeConfig(baseConfig())

	got := s.ConfigFor("busy")
	if got.GetInbounds()[0].GetPort() != 2053 || got.GetInbounds()[1].GetPort() != 2083 {
		t.Errorf("ports = %d/%d, want the offered 2053/2083",
			got.GetInbounds()[0].GetPort(), got.GetInbounds()[1].GetPort())
	}

	// A node that offered nothing keeps the fleet default, and the override must
	// not have leaked into the shared config.
	if p := s.ConfigFor("plain").GetInbounds()[0].GetPort(); p != 443 {
		t.Errorf("untouched node got port %d, want 443", p)
	}
	if p := s.CurrentConfig().GetInbounds()[0].GetPort(); p != 443 {
		t.Errorf("the fleet config was mutated to %d", p)
	}
}

// Ноде должен уезжать её собственный конфиг, а не общий: порты и заимствованная
// личность у каждой свои. Общий конфиг сажал весь флот на одну пару портов -
// именно ту, которую нода занять и не могла.
func TestConfigForIsWhatANodeGets(t *testing.T) {
	reg := registry.New()
	reg.Add(&registry.Node{ID: "n1", OfferedPorts: []uint32{58384, 28822}})
	reg.Add(&registry.Node{ID: "n2", OfferedPorts: []uint32{46997, 50538}})

	s := New(reg, nil, "head:443")
	s.SetNodeConfig(baseConfig())

	first := s.ConfigFor("n1").GetInbounds()
	second := s.ConfigFor("n2").GetInbounds()
	if first[0].GetPort() == second[0].GetPort() {
		t.Errorf("обе ноды получили порт %d", first[0].GetPort())
	}
	if first[0].GetPort() != 58384 || second[1].GetPort() != 50538 {
		t.Errorf("порты не те: %d и %d", first[0].GetPort(), second[1].GetPort())
	}
}

// Смена настроек должна доезжать до уже подключённых нод. Пока push случался
// только на hello, изменение висело до переподключения - оператор сохранял
// настройку и часами не видел никакого эффекта.
func TestChangingTheConfigReachesConnectedNodes(t *testing.T) {
	reg := registry.New()
	reg.Add(&registry.Node{ID: "n1", OfferedPorts: []uint32{8443, 8444}})

	s := New(reg, nil, "head:443")
	sess := s.register("n1")
	t.Cleanup(func() { s.deregister("n1", sess) })

	s.SetNodeConfig(baseConfig())

	select {
	case frame := <-sess.out:
		push := frame.GetConfigPush()
		if push == nil {
			t.Fatalf("в сессию ушёл не конфиг: %T", frame.GetFrame())
		}
		if push.GetInbounds()[0].GetPort() != 8443 {
			t.Errorf("ноде уехал чужой порт: %d", push.GetInbounds()[0].GetPort())
		}
	default:
		t.Fatal("подключённая нода не получила новый конфиг")
	}
}
