package nodeid

import "testing"

// The fingerprint must not move between calls on the same machine: a node whose
// identity drifts re-enrolls as a stranger and starts a second budget
func TestFingerprintIsStable(t *testing.T) {
	first := Fingerprint("")
	second := Fingerprint("")
	if first != second {
		t.Errorf("fingerprint drifted between calls: %q vs %q", first, second)
	}
	if len(first) != 32 {
		t.Errorf("fingerprint = %q, want 32 hex chars", first)
	}
}

// Salt exists so an operator can deliberately split hosts cloned from one image,
// which share a machine id
func TestSaltSeparatesClones(t *testing.T) {
	if Fingerprint("a") == Fingerprint("b") {
		t.Error("different salts produced the same fingerprint")
	}
}

// Interfaces that appear and vanish must not be part of the identity, or every
// container start would rename the node
func TestVirtualInterfacesAreIgnored(t *testing.T) {
	for _, name := range []string{"docker0", "veth1234", "br-abc", "wg-wingsv", "tun0"} {
		if !isVirtual(name) {
			t.Errorf("%q should be treated as virtual", name)
		}
	}
	for _, name := range []string{"eth0", "ens3", "enp1s0", "wlan0"} {
		if isVirtual(name) {
			t.Errorf("%q should be treated as real", name)
		}
	}
}
