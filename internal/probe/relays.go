package probe

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/dialpick"
)

// maxRelays - сколько запасных путей помним. Флот может быть большой, а
// перебирать сотню адресов на каждом заходе бессмысленно: если не отвечают
// первые несколько, дело не в них
const maxRelays = 8

// rememberRelays собирает адреса нод из задания и кладёт их в перебор.
//
// Ноды доступны из страны по определению, иначе через них не ходили бы люди, а
// вот адрес башки закрывают целиком, и тогда все её адреса мертвы одинаково
func rememberRelays(cfg Config, picker *dialpick.Picker, task *fedpb.ProbeTask) {
	if cfg.RelayPort <= 0 {
		return
	}
	seen := map[string]struct{}{}
	relays := make([]string, 0, maxRelays)
	for _, target := range task.GetTargets() {
		host := strings.TrimSpace(target.GetHost())
		if host == "" || isIPv6(host) {
			continue
		}
		addr := net.JoinHostPort(host, strconv.Itoa(cfg.RelayPort))
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		relays = append(relays, addr)
		if len(relays) >= maxRelays {
			break
		}
	}
	if len(relays) == 0 {
		return
	}
	sort.Strings(relays)
	// Заданные руками не теряем: узнанное из задания дополняет их, а не
	// заменяет
	relays = dedupRelays(append(append([]string(nil), cfg.Relays...), relays...))
	picker.SetRelays(relays)
	saveRelays(cfg.RelayCache, relays)
}

// dedupRelays схлопывает повторы, сохраняя порядок: заданные руками важнее
// узнанных, потому и идут первыми
func dedupRelays(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, addr := range in {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// loadRelays поднимает пути, узнанные в прошлой жизни
func loadRelays(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// saveRelays складывает пути на диск через временный файл: оборванная запись не
// должна оставить зонд с огрызком вместо списка
func saveRelays(path string, relays []string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(relays, "\n")+"\n"), 0o600); err != nil {
		log.Printf("probe: fallback paths were not stored: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("probe: fallback paths were not renamed: %v", err)
	}
}
