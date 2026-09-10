// Package portgate открывает порт данных на самом хосте.
//
// Порт релея выбирается под каждую ноду отдельно, поэтому вписать его в правила
// заранее нельзя, а хост с политикой DROP молча съедает весь DTLS: релей при
// этом слушает, рапортует готовность и не видит ни одного пакета. Диагностика
// такого стоит вечера, поэтому нода открывает свой порт сама
package portgate

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// commandTimeout - потолок на одну команду. Правила ставятся быстро, а зависший
// вызов не должен держать запуск ноды
const commandTimeout = 10 * time.Second

// ErrNoTool means the host has neither ufw nor iptables
var ErrNoTool = errors.New("portgate: neither ufw nor iptables is available")

// Rule - один порт, который нода обязана слышать снаружи
type Rule struct {
	Port  uint32
	Proto string
	// What - чей это порт, для строки в лог. Человек, читающий её на чужом
	// сервере, должен понимать, что мы ему открыли и зачем
	What string
}

// OpenUDP разрешает входящий udp на этот порт
func OpenUDP(ctx context.Context, port uint32) error {
	return Open(ctx, Rule{Port: port, Proto: "udp"})
}

// OpenTCP разрешает входящий tcp на этот порт
func OpenTCP(ctx context.Context, port uint32) error {
	return Open(ctx, Rule{Port: port, Proto: "tcp"})
}

// Open пробивает один порт.
//
// Сначала ufw: на хосте, где он включён, правило переживёт перезагрузку, а
// правка iptables мимо него - нет. Без ufw ставим правило напрямую, и тогда его
// придётся ставить заново при каждом старте, что агент и делает
func Open(ctx context.Context, rule Rule) error {
	proto := strings.ToLower(strings.TrimSpace(rule.Proto))
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("portgate: %q is not a protocol we open", rule.Proto)
	}
	if rule.Port == 0 || rule.Port > 65535 {
		return fmt.Errorf("portgate: port %d is out of range", rule.Port)
	}
	number := strconv.FormatUint(uint64(rule.Port), 10)
	label := strings.TrimSpace(rule.What)
	if label == "" {
		label = "node"
	}
	if ufwActive(ctx) {
		if err := run(ctx, "ufw", "allow", number+"/"+proto); err != nil {
			return fmt.Errorf("portgate: ufw allow %s/%s: %w", number, proto, err)
		}
		log.Printf("portgate: ufw now allows %s %s (%s)", proto, number, label)
		return nil
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return ErrNoTool
	}
	// Проверяем перед вставкой: агент ставит правила на каждом старте, и без
	// этого их накапливается по набору за запуск
	if run(ctx, "iptables", "-C", "INPUT", "-p", proto, "--dport", number, "-j", "ACCEPT") == nil {
		return nil
	}
	if err := run(ctx, "iptables", "-I", "INPUT", "-p", proto, "--dport", number, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("portgate: iptables accept %s %s: %w", proto, number, err)
	}
	log.Printf("portgate: iptables now accepts %s %s (%s)", proto, number, label)
	return nil
}

// OpenAll пробивает весь набор и возвращает первую поломку, дойдя до конца.
//
// Ошибка на одном порту не повод бросить остальные: нода с открытым Xray и
// закрытым релеем полезнее, чем закрытая целиком, а человеку в лог всё равно
// уедет, чего именно не хватило
func OpenAll(ctx context.Context, rules []Rule) error {
	seen := make(map[string]bool, len(rules))
	var failed error
	for _, rule := range rules {
		key := strings.ToLower(rule.Proto) + ":" + strconv.FormatUint(uint64(rule.Port), 10)
		if rule.Port == 0 || seen[key] {
			continue
		}
		seen[key] = true
		if err := Open(ctx, rule); err != nil && failed == nil {
			failed = err
		}
	}
	return failed
}

// ufwActive - включён ли ufw. Установленный, но выключенный ufw правил не
// применяет, и правило в нём осталось бы декорацией
func ufwActive(ctx context.Context) bool {
	if _, err := exec.LookPath("ufw"); err != nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ufw", "status").CombinedOutput()
	if err != nil {
		return false
	}
	return containsActive(string(out))
}

func containsActive(status string) bool {
	for _, marker := range []string{"Status: active", "Состояние: активен"} {
		if strings.Contains(status, marker) {
			return true
		}
	}
	return false
}

func run(ctx context.Context, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", name, err, out)
	}
	return nil
}
