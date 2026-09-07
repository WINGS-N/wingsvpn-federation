package portpick

import (
	"fmt"
	"net"
	"testing"
)

func occupy(t *testing.T, port uint32) {
	t.Helper()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Skipf("cannot occupy %d here: %v", port, err)
	}
	t.Cleanup(func() { _ = lis.Close() })
}

func freePort(t *testing.T) uint32 {
	t.Helper()
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	return uint32(lis.Addr().(*net.TCPAddr).Port)
}

func TestPickSkipsABusyPort(t *testing.T) {
	busy := freePort(t)
	spare := freePort(t)
	occupy(t, busy)

	got, err := Pick([]uint32{busy, spare})
	if err != nil {
		t.Fatal(err)
	}
	if got != spare {
		t.Errorf("Pick = %d, want the free port %d", got, spare)
	}
}

func TestPickHonoursTaken(t *testing.T) {
	first := freePort(t)
	second := freePort(t)
	got, err := Pick([]uint32{first, second}, first)
	if err != nil {
		t.Fatal(err)
	}
	if got != second {
		t.Errorf("Pick = %d, want %d: the first was already claimed", got, first)
	}
}

func TestPickReportsWhenEverythingIsTaken(t *testing.T) {
	busy := freePort(t)
	occupy(t, busy)
	if _, err := Pick([]uint32{busy}); err == nil {
		t.Fatal("Pick succeeded with no free candidate")
	}
}

// The two inbounds must never land on one port: Xray would fail to start and
// the node would look enrolled while serving nothing.
func TestAutoKeepsThePortsDistinct(t *testing.T) {
	tcp, xhttp, err := Auto("node-fingerprint")
	if err != nil {
		t.Skipf("no free candidate on this host: %v", err)
	}
	if tcp == xhttp {
		t.Errorf("Auto returned %d for both inbounds", tcp)
	}
}

// Порт должен держаться за хост, а не за запуск: башка проверяет адрес зондом,
// и порт, меняющийся на каждом рестарте, делает эту проверку бессмысленной.
func TestDerivedPortIsStablePerHost(t *testing.T) {
	first := Derived("fingerprint-a", "tcp")
	if second := Derived("fingerprint-a", "tcp"); first != second {
		t.Errorf("один хост дал разные порты: %d и %d", first, second)
	}
	if other := Derived("fingerprint-b", "tcp"); other == first {
		t.Error("разные хосты получили один порт: флот блокируется одним правилом")
	}
	if same := Derived("fingerprint-a", "xhttp"); same == first {
		t.Error("оба инбаунда на одном порту")
	}
}

// Главное свойство: не попадать в списки, которые цензор блокирует пачкой.
// 8443, 2053, 2083 и прочий набор Cloudflare есть в каждой методичке.
func TestDerivedPortAvoidsTheWellKnownSet(t *testing.T) {
	burned := map[uint32]bool{80: true, 443: true, 8080: true, 8443: true,
		2053: true, 2083: true, 2087: true, 2096: true}
	for _, seed := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		got := Derived(seed, "tcp")
		if burned[got] {
			t.Errorf("seed %q дал засвеченный порт %d", seed, got)
		}
		if got < derivedLow || got >= derivedHigh {
			t.Errorf("seed %q дал порт %d вне диапазона", seed, got)
		}
	}
}

// hostPort в кубере - это DNAT в PREROUTING без сокета: bind проходит, а пакеты
// забирает чужое правило, и изнутри пода это не видно никак. Поэтому исключение
// должно работать даже для порта, который свободен по всем признакам.
func TestExcludedPortIsSkippedThoughItBinds(t *testing.T) {
	tcp, xhttp, err := Auto("node-fingerprint", 443)
	if err != nil {
		t.Skipf("нет свободного кандидата: %v", err)
	}
	if tcp == 443 || xhttp == 443 {
		t.Errorf("исключённый 443 всё равно выбран: tcp=%d xhttp=%d", tcp, xhttp)
	}
	if tcp == xhttp {
		t.Errorf("оба инбаунда на одном порту: %d", tcp)
	}
}

func TestUDPIsStableForAHost(t *testing.T) {
	first, err := UDP("node-fingerprint", 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := UDP("node-fingerprint", 0)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("порт скачет между заходами: %d и %d", first, second)
	}
	other, err := UDP("another-fingerprint", 0)
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("два разных хоста получили один порт")
	}
	if first < 20000 || first > 60000 {
		t.Fatalf("порт %d вне диапазона", first)
	}
	if first == 56000 {
		t.Fatal("выдали то самое число, которое всех и палит")
	}
}

// Занятый порт обязан быть пропущен, а не выдан вторым претендентом
func TestUDPWalksAwayFromABusyPort(t *testing.T) {
	taken, err := UDP("busy-host", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", taken))
	if err != nil {
		t.Skipf("не удалось занять %d: %v", taken, err)
	}
	defer func() { _ = conn.Close() }()
	next, err := UDP("busy-host", 0)
	if err != nil {
		t.Fatal(err)
	}
	if next == taken {
		t.Fatalf("выдали занятый порт %d", taken)
	}
}

// Свой же сокет не повод убегать на соседний порт: без этого ответ уходил на
// один вперёд при каждом вызове, и релей переезжал каждые полминуты
func TestUDPKeepsThePortTheCallerAlreadyHolds(t *testing.T) {
	want, err := UDP("held-host", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", want))
	if err != nil {
		t.Skipf("не удалось занять %d: %v", want, err)
	}
	defer func() { _ = conn.Close() }()
	got, err := UDP("held-host", want)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("свой порт %d сменили на %d", want, got)
	}
}
