// Package portpick chooses the ports a node can actually serve on.
//
// 443 is what makes a REALITY inbound indistinguishable from an ordinary web
// server, so it is always tried first. But a donated host very often already has
// something there, and refusing such a host would turn away most of the machines
// people actually have. So a busy port is a reason to move, not to give up.
//
// What it moves to is deliberately NOT the well-known alternates - 8443, 2053,
// 2083 and the rest of the Cloudflare set. Those appear in every circumvention
// guide, which makes them a list a censor can block in one rule, and a node
// sitting on one is easier to spot than a node on a port nobody enumerated. The
// fallback is instead derived from the node's own fingerprint: stable across
// restarts, different on every host, and belonging to no published list.
package portpick

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// TCPDefaults is the preference order for the REALITY tcp inbound. One entry on
// purpose: everything after 443 is guesswork, and guessing from a published list
// is worse than picking a port nobody published.
var TCPDefaults = []uint32{443}

// XHTTPDefaults holds no well-known port for the same reason. The xhttp inbound
// never gets 443 anyway - the tcp one takes it - so it goes straight to a port
// derived from the host.
var XHTTPDefaults = []uint32{}

// derivedRange bounds the fallback. High enough to sit above anything a distro
// starts by default, wide enough that scanning the fleet is not a short job.
const (
	derivedLow  = 20000
	derivedHigh = 60000
)

// Derived returns a stable port for this host, unrelated to any published list.
//
// The same seed always yields the same port, so a node keeps its port across
// restarts and the head does not have to be told about a new one; salt separates
// the two inbounds on the same host.
func Derived(seed, salt string) uint32 {
	sum := sha512.Sum512_256([]byte(seed + "/" + salt))
	n := binary.BigEndian.Uint32(sum[:4])
	return derivedLow + n%(derivedHigh-derivedLow)
}

// ErrNoFreePort means every candidate was taken
var ErrNoFreePort = errors.New("portpick: no candidate port is free")

// Free reports whether the port can be bound on all interfaces.
//
// It binds rather than scans: a listener elsewhere in the same network
// namespace is exactly what would break Xray at startup, and only an actual
// bind sees it. The socket is closed immediately, so there is a race with
// anything else racing for the port - which is why the agent picks late, just
// before it enrols, and not hours ahead.
func Free(port uint32) bool {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = lis.Close()
	return true
}

// Pick returns the first free candidate, skipping any port in taken.
func Pick(candidates []uint32, taken ...uint32) (uint32, error) {
	busy := make(map[uint32]bool, len(taken))
	for _, p := range taken {
		busy[p] = true
	}
	for _, p := range candidates {
		if busy[p] || !Free(p) {
			continue
		}
		return p, nil
	}
	return 0, ErrNoFreePort
}

// Auto picks the tcp and xhttp ports for this host, keeping them distinct.
//
// seed is what the derived fallback is built from - the node fingerprint - so
// the choice survives a restart. An empty seed still works, it just makes the
// port random per process, which is the wrong trade for a node the head has
// already probed.
//
// exclude names ports the caller knows are unusable even though they bind. That
// is not a hypothetical: a Kubernetes hostPort is DNAT in PREROUTING with no
// socket in the host namespace, so binding 443 succeeds while every packet is
// taken by the other rule first - and nothing inside the pod can see it.
func Auto(seed string, exclude ...uint32) (tcp, xhttp uint32, err error) {
	tcp, err = Pick(TCPDefaults, exclude...)
	if err != nil {
		tcp, err = pickDerived(seed, "tcp", exclude...)
		if err != nil {
			return 0, 0, err
		}
	}
	xhttp, err = pickDerived(seed, "xhttp", append(exclude, tcp)...)
	if err != nil {
		return 0, 0, err
	}
	return tcp, xhttp, nil
}

// pickDerived walks away from the derived port until it finds a free one, so a
// collision costs a few tries rather than the whole enrolment.
func pickDerived(seed, salt string, taken ...uint32) (uint32, error) {
	busy := make(map[uint32]bool, len(taken))
	for _, p := range taken {
		busy[p] = true
	}
	start := Derived(seed, salt)
	for i := uint32(0); i < 64; i++ {
		port := derivedLow + (start-derivedLow+i)%(derivedHigh-derivedLow)
		if busy[port] || !Free(port) {
			continue
		}
		return port, nil
	}
	return 0, ErrNoFreePort
}

// FreeUDP reports whether the udp port can be bound on all interfaces.
//
// A tcp bind proves nothing here: the two live in separate port spaces, and the
// relay's data plane is udp only. Same race as Free - pick late, not early.
func FreeUDP(port uint32) bool {
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// UDP returns the udp port this host serves the relay data plane on.
//
// The well-known 56000 is deliberately not tried: it names the software as
// plainly as a banner would, and a censor blocking one number costs us every
// node at once. The port is derived from the fingerprint instead, so it is
// stable across restarts, different on every host and on no published list -
// the same trade the inbounds already make.
//
// owned is the port the caller is already listening on. It counts as free even
// though it binds: without that the answer walks one port forward on every call
// - the relay holds the derived port, so the check sees it taken and picks the
// next one, which the relay then holds, and so on every time it is asked.
func UDP(seed string, owned uint32, exclude ...uint32) (uint32, error) {
	busy := make(map[uint32]bool, len(exclude))
	for _, p := range exclude {
		busy[p] = true
	}
	start := Derived(seed, "vktp")
	for i := uint32(0); i < 64; i++ {
		port := derivedLow + (start-derivedLow+i)%(derivedHigh-derivedLow)
		if busy[port] {
			continue
		}
		if port == owned || FreeUDP(port) {
			return port, nil
		}
	}
	return 0, ErrNoFreePort
}
