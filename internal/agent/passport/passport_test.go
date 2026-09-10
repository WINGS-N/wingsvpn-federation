package passport

import "testing"

// A box behind NAT sees no public address of its own. Without a way to pin one
// it reports nothing routable and stays unreachable forever however healthy it is
func TestConfiguredAddressesAreKeptAndLabelled(t *testing.T) {
	got := Configured([]string{"203.0.113.7", " 198.51.100.9:443 ", "2001:db8::1"})
	if len(got) != 3 {
		t.Fatalf("got %d addresses, want 3", len(got))
	}
	if got[0].GetAddress() != "203.0.113.7" || got[0].GetIpv6() {
		t.Errorf("first = %+v", got[0])
	}
	// A port is not part of an address here: the head pairs it with the inbound
	if got[1].GetAddress() != "198.51.100.9" {
		t.Errorf("second = %q, want the port stripped", got[1].GetAddress())
	}
	if !got[2].GetIpv6() {
		t.Errorf("third = %+v, want it marked v6", got[2])
	}
	for _, a := range got {
		if a.GetSource() != "configured" {
			t.Errorf("source = %q, want configured so the head can tell it apart", a.GetSource())
		}
	}
}

func TestNonsenseAddressesAreDropped(t *testing.T) {
	if got := Configured([]string{"", "   ", "not-an-ip", "example.com"}); len(got) != 0 {
		t.Errorf("got %+v, want nothing", got)
	}
}

// The pinned address has to reach the passport, or the flag is decoration
func TestCollectIncludesConfiguredAddresses(t *testing.T) {
	p := Collect("test", "203.0.113.7")
	var found bool
	for _, a := range p.GetAddresses() {
		if a.GetAddress() == "203.0.113.7" && a.GetSource() == "configured" {
			found = true
		}
	}
	if !found {
		t.Errorf("pinned address missing from the passport: %+v", p.GetAddresses())
	}
}
