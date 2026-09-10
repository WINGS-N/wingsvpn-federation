// Package shaper режет скорость пира VK TURN.
//
// У релея ограничителя нет вообще: ни в его API, ни внутри. Зато WireGuard
// терминируется ядром прямо на ноде, у каждого пира свой /32 из allowed_ips, и
// ядро умеет шейпить по адресу само. Режем там, где оно и должно резаться - в
// ядре, а не в чужом процессе
package shaper

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// commandTimeout - tc отвечает мгновенно или не отвечает вовсе
const commandTimeout = 5 * time.Second

// rootHandle - корень дерева классов. Своя ветка, чтобы не топтаться по чужим
// правилам, если они на ноде уже стоят
const rootHandle = "1:"

// unlimitedRate - полоса класса без потолка. Ноль htb не понимает, поэтому
// ставим заведомо больше любого канала ноды
const unlimitedRate = "10gbit"

// Limit - потолок одного пира, байт в секунду. Ноль означает "без потолка"
type Limit struct {
	DownBps uint64
}

// Shaper держит потолки скорости на wg-интерфейсе
type Shaper struct {
	iface string
	run   func(ctx context.Context, args ...string) error

	mu sync.Mutex
	// applied - что уже стоит, чтобы не дёргать ядро на каждом круге
	applied map[string]Limit
	// classes - какой класс достался адресу
	classes map[string]int
	nextID  int
	ready   bool
}

func New(iface string) *Shaper {
	return &Shaper{
		iface:   iface,
		run:     runTC,
		applied: map[string]Limit{},
		classes: map[string]int{},
		nextID:  10,
	}
}

// SetRunner подменяет вызов tc. Нужно тестам: гонять ядерные команды на сборке
// нельзя, а логику проверять надо
func (s *Shaper) SetRunner(run func(ctx context.Context, args ...string) error) {
	s.run = run
}

// Apply ставит потолок пиру.
//
// Ограничиваем то, что человек КАЧАЕТ: отдача у него и так упирается в его
// собственный канал, а шейпить её пришлось бы на его стороне
func (s *Shaper) Apply(ctx context.Context, allowedIPs string, limit Limit) error {
	addr := hostOf(allowedIPs)
	if addr == "" {
		return fmt.Errorf("shaper: unparsable peer address %q", allowedIPs)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if was, ok := s.applied[addr]; ok && was == limit {
		return nil
	}
	if err := s.ensureRootLocked(ctx); err != nil {
		return err
	}
	class, ok := s.classes[addr]
	if !ok {
		class = s.nextID
		s.nextID++
		s.classes[addr] = class
	}
	rate := unlimitedRate
	if limit.DownBps > 0 {
		rate = fmt.Sprintf("%dbit", limit.DownBps*8)
	}
	classID := fmt.Sprintf("1:%d", class)
	if err := s.run(ctx, "class", "replace", "dev", s.iface, "parent", rootHandle,
		"classid", classID, "htb", "rate", rate); err != nil {
		return err
	}
	if err := s.run(ctx, "filter", "replace", "dev", s.iface, "protocol", "ip",
		"parent", rootHandle, "prio", "1", "u32",
		"match", "ip", "dst", addr+"/32", "flowid", classID); err != nil {
		return err
	}
	s.applied[addr] = limit
	return nil
}

// Forget снимает всё, что помнили про адрес: пира отозвали
func (s *Shaper) Forget(ctx context.Context, allowedIPs string) {
	addr := hostOf(allowedIPs)
	s.mu.Lock()
	class, ok := s.classes[addr]
	delete(s.classes, addr)
	delete(s.applied, addr)
	s.mu.Unlock()
	if !ok {
		return
	}
	_ = s.run(ctx, "class", "del", "dev", s.iface, "classid", fmt.Sprintf("1:%d", class))
}

// ensureRootLocked заводит корень дерева. Держит замок вызывающий
func (s *Shaper) ensureRootLocked(ctx context.Context) error {
	if s.ready {
		return nil
	}
	// Класс по умолчанию нужен обязательно: без него всё, чему не досталось
	// своего класса, ушло бы в общую очередь и тормозило вместе с наказанными
	if err := s.run(ctx, "qdisc", "replace", "dev", s.iface, "root", "handle", rootHandle,
		"htb", "default", "1"); err != nil {
		return err
	}
	s.ready = true
	return nil
}

// hostOf достаёт адрес из allowed_ips вида 10.8.0.5/32
func hostOf(allowedIPs string) string {
	first := strings.TrimSpace(strings.Split(allowedIPs, ",")[0])
	if first == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(first); err == nil {
		return ip.String()
	}
	if ip := net.ParseIP(first); ip != nil {
		return ip.String()
	}
	return ""
}

func runTC(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
