// Package nodeid derives the stable fingerprint a machine presents when it
// enrolls. Re-running the installer on the same server must be recognised as the
// same node rather than forking a second identity that keeps its own budget
package nodeid

import (
	"crypto/sha512"
	"encoding/hex"
	"net"
	"os"
	"sort"
	"strings"
)

// machineIDPaths are the usual homes of the host's stable id. dbus keeps a copy
// on systems where systemd does not own the file
var machineIDPaths = []string{
	"/etc/machine-id",
	"/var/lib/dbus/machine-id",
}

// Fingerprint derives a stable per-machine identifier.
//
// The machine id alone is not enough: cloud images are frequently cloned with it
// baked in, so two servers from the same snapshot would claim one identity. The
// hardware addresses disambiguate those, and salt lets an operator deliberately
// split a node that was cloned on purpose
func Fingerprint(salt string) string {
	parts := []string{"wingsv-fed-node-v1", strings.TrimSpace(salt), machineID()}
	parts = append(parts, hardwareAddrs()...)
	sum := sha512.Sum512([]byte(strings.Join(parts, "|")))
	// Half of SHA-512 is plenty to name a node and keeps the value readable in
	// logs; this is an identifier, not a secret
	return hex.EncodeToString(sum[:16])
}

func machineID() string {
	for _, path := range machineIDPaths {
		data, err := os.ReadFile(path)
		if err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	// A host without a machine id still gets a usable fingerprint from its
	// hardware addresses; the hostname keeps two such hosts apart
	host, _ := os.Hostname()
	return "nohostid:" + host
}

// hardwareAddrs returns the sorted MACs of real interfaces. Loopback and
// virtual devices are skipped because docker and wireguard interfaces come and
// go, and a fingerprint that changes when a container starts is worthless
func hardwareAddrs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		if isVirtual(iface.Name) {
			continue
		}
		out = append(out, iface.HardwareAddr.String())
	}
	sort.Strings(out)
	return out
}

var virtualPrefixes = []string{"docker", "veth", "br-", "virbr", "wg", "tun", "tap", "cni", "flannel"}

func isVirtual(name string) bool {
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
