// Package passport describes the machine to the head
package passport

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Collect builds the passport sent at enrollment.
//
// configured are addresses the operator pinned by hand. They are needed whenever
// the machine cannot see its own public address: a box behind NAT with a port
// forward, or a provider that hands out a floating address the interface never
// holds. Without them such a node reports nothing routable and is unreachable
// forever however healthy it is
func Collect(agentVersion string, configured ...string) *fedpb.NodePassport {
	return CollectWith(agentVersion, Declared{}, configured...)
}

// Declared is what the operator states about the machine, which nothing on it
// can work out for itself
type Declared struct {
	ASN     string
	Country string
}

// CollectWith builds the passport including operator-declared facts
func CollectWith(agentVersion string, declared Declared, configured ...string) *fedpb.NodePassport {
	host, _ := os.Hostname()
	return &fedpb.NodePassport{
		Asn:               declared.ASN,
		Country:           declared.Country,
		Hostname:          host,
		Addresses:         append(Addresses(), Configured(configured)...),
		Arch:              runtime.GOARCH,
		Os:                runtime.GOOS,
		Kernel:            kernelRelease(),
		CpuCores:          uint32(runtime.NumCPU()),
		MemBytes:          memTotal(),
		AgentVersion:      agentVersion,
		HasRoot:           os.Geteuid() == 0,
		KernelWgAvailable: kernelWireGuard(),
		AesNi:             hasAESNI(),
	}
}

// Addresses lists the routable addresses this machine sees on itself. They are
// candidates only: a provider can move a server and leave the old address in
// place, so nothing here counts until a probe confirms it
func Addresses() []*fedpb.NodeAddress {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	outbound := outboundIPs()
	now := time.Now().Unix()
	var out []*fedpb.NodeAddress
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || !routable(ipnet.IP) {
				continue
			}
			// Только адреса того интерфейса, через который нода реально выходит
			// наружу. Мосты докера и панелей берут себе чужие публичные блоки,
			// и зонд потом честно меряет их до таймаута
			if len(outbound) > 0 && !outbound[ipnet.IP.String()] {
				continue
			}
			out = append(out, &fedpb.NodeAddress{
				Address:       ipnet.IP.String(),
				Ipv6:          ipnet.IP.To4() == nil,
				Source:        "reported",
				FirstSeenUnix: now,
			})
		}
	}
	return out
}

// outboundIPs - адреса, с которых машина уходит в интернет. Пустое множество
// означает, что определить не вышло, и тогда берутся все маршрутизируемые
func outboundIPs() map[string]bool {
	out := map[string]bool{}
	for _, target := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		conn, err := net.DialTimeout("udp", target, 2*time.Second)
		if err != nil {
			continue
		}
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
			out[addr.IP.String()] = true
		}
		_ = conn.Close()
	}
	return out
}

// Configured turns operator-pinned addresses into passport entries. Marked as
// their own source, because the head trusts these no further than the reported
// ones: only a probe decides what actually works
func Configured(addrs []string) []*fedpb.NodeAddress {
	now := time.Now().Unix()
	var out []*fedpb.NodeAddress
	for _, raw := range addrs {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		out = append(out, &fedpb.NodeAddress{
			Address:       ip.String(),
			Ipv6:          ip.To4() == nil,
			Source:        "configured",
			FirstSeenUnix: now,
		})
	}
	return out
}

func routable(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsPrivate()
}

// hasAESNI decides which WRAP cipher suits this node. Without the flag AES runs
// in software and ChaCha20 is materially faster
func hasAESNI() bool {
	return cpuFlag("aes")
}

func cpuFlag(flag string) bool {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "flags") && !strings.HasPrefix(line, "Features") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if field == flag {
				return true
			}
		}
	}
	return false
}

func kernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func memTotal() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			var kb uint64
			for _, c := range fields[1] {
				if c < '0' || c > '9' {
					break
				}
				kb = kb*10 + uint64(c-'0')
			}
			return kb * 1024
		}
	}
	return 0
}

// kernelWireGuard reports whether the in-tree module is available. The relay's
// own-wg path needs it, and loading it is the relay's job, not ours
func kernelWireGuard() bool {
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		return true
	}
	matches, _ := os.ReadDir("/lib/modules")
	for _, entry := range matches {
		path := "/lib/modules/" + entry.Name() + "/kernel/drivers/net/wireguard"
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}
