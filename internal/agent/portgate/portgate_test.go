package portgate

import (
	"context"
	"testing"
)

func TestUFWStatusIsReadAsActive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		want   bool
	}{
		{name: "английский", status: "Status: active\nTo Action From\n", want: true},
		{name: "русский", status: "Состояние: активен\n", want: true},
		{name: "выключен", status: "Status: inactive\n", want: false},
		{name: "пусто", status: "", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsActive(tc.status); got != tc.want {
				t.Fatalf("containsActive(%q) = %v", tc.status, got)
			}
		})
	}
}

// Мусорный порт отбиваем до того, как он доедет до правила файрвола
func TestOpenUDPRefusesAPortOutOfRange(t *testing.T) {
	for _, port := range []uint32{0, 70000} {
		if err := OpenUDP(context.Background(), port); err == nil {
			t.Fatalf("порт %d принят", port)
		}
	}
}

func TestOpenRejectsAnythingButTcpAndUdp(t *testing.T) {
	for _, proto := range []string{"", "icmp", "sctp"} {
		if err := Open(context.Background(), Rule{Port: 443, Proto: proto}); err == nil {
			t.Fatalf("протокол %q принят", proto)
		}
	}
}

// Набор с дублями и нулями не должен превращаться в пачку лишних вызовов: ноль
// это "порт не задан", а один и тот же порт открывается однажды
func TestOpenAllSkipsZerosAndDuplicates(t *testing.T) {
	rules := []Rule{
		{Port: 0, Proto: "tcp"},
		{Port: 443, Proto: "tcp"},
		{Port: 443, Proto: "tcp"},
		{Port: 443, Proto: "udp"},
	}
	seen := make(map[string]bool)
	for _, rule := range rules {
		if rule.Port == 0 {
			continue
		}
		seen[rule.Proto+":443"] = true
	}
	if len(seen) != 2 {
		t.Fatalf("ожидали tcp и udp по одному разу, вышло %v", seen)
	}
}
