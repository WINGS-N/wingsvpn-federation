package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

func newReceipt() *fedpb.TrafficReceipt {
	return &fedpb.TrafficReceipt{
		ClientId:         "c1",
		NodeId:           "n1",
		WindowStartUnix:  1000,
		WindowEndUnix:    2000,
		PayloadUpBytes:   500,
		PayloadDownBytes: 9000,
		Transport:        TransportXray,
		Nonce:            "nonce-1",
	}
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := keys(t)
	r := newReceipt()
	if err := Sign(priv, r); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, r); err != nil {
		t.Errorf("a freshly signed receipt did not verify: %v", err)
	}
}

// The whole point: a node must not be able to inflate what a client received
func TestTamperedVolumeFailsVerification(t *testing.T) {
	pub, priv := keys(t)
	r := newReceipt()
	if err := Sign(priv, r); err != nil {
		t.Fatal(err)
	}
	r.PayloadDownBytes = 10 << 30
	if err := Verify(pub, r); err != ErrBadSignature {
		t.Errorf("an inflated receipt verified: %v", err)
	}
}

// Every signed field has to be covered, or a node edits the one that is not
func TestEveryFieldIsCovered(t *testing.T) {
	pub, priv := keys(t)
	mutations := map[string]func(*fedpb.TrafficReceipt){
		"client":       func(r *fedpb.TrafficReceipt) { r.ClientId = "other" },
		"node":         func(r *fedpb.TrafficReceipt) { r.NodeId = "other" },
		"nonce":        func(r *fedpb.TrafficReceipt) { r.Nonce = "other" },
		"window start": func(r *fedpb.TrafficReceipt) { r.WindowStartUnix = 1 },
		"window end":   func(r *fedpb.TrafficReceipt) { r.WindowEndUnix = 99999 },
		"up":           func(r *fedpb.TrafficReceipt) { r.PayloadUpBytes = 1 },
		"down":         func(r *fedpb.TrafficReceipt) { r.PayloadDownBytes = 1 },
	}
	for name, mutate := range mutations {
		r := newReceipt()
		if err := Sign(priv, r); err != nil {
			t.Fatal(err)
		}
		mutate(r)
		if err := Verify(pub, r); err == nil {
			t.Errorf("%s was not covered by the signature", name)
		}
	}
}

// A receipt signed by somebody else must not pass, or a donor signs their own
func TestForeignKeyIsRejected(t *testing.T) {
	_, priv := keys(t)
	otherPub, _ := keys(t)
	r := newReceipt()
	if err := Sign(priv, r); err != nil {
		t.Fatal(err)
	}
	if err := Verify(otherPub, r); err != ErrBadSignature {
		t.Errorf("a receipt verified against the wrong key: %v", err)
	}
}

// The domain prefix keeps a receipt from being replayed as some other signed
// message the same key produces
func TestCanonicalIsDomainSeparated(t *testing.T) {
	r := newReceipt()
	if got := string(Canonical(r)[:len(domain)]); got != domain {
		t.Errorf("canonical bytes do not start with the domain prefix")
	}
}

// Two receipts differing only in field boundaries must not collide: without
// length prefixes, "ab"+"c" and "a"+"bc" would sign identically
func TestFieldBoundariesCannotCollide(t *testing.T) {
	a := newReceipt()
	a.ClientId, a.NodeId = "ab", "c"
	b := newReceipt()
	b.ClientId, b.NodeId = "a", "bc"
	if string(Canonical(a)) == string(Canonical(b)) {
		t.Error("two different receipts produced the same canonical bytes")
	}
}

func TestMalformedIsRejected(t *testing.T) {
	pub, priv := keys(t)
	cases := map[string]func(*fedpb.TrafficReceipt){
		"no client":        func(r *fedpb.TrafficReceipt) { r.ClientId = "" },
		"no node":          func(r *fedpb.TrafficReceipt) { r.NodeId = "" },
		"no nonce":         func(r *fedpb.TrafficReceipt) { r.Nonce = "" },
		"backwards window": func(r *fedpb.TrafficReceipt) { r.WindowEndUnix = 500 },
		"zero window":      func(r *fedpb.TrafficReceipt) { r.WindowEndUnix = r.WindowStartUnix },
	}
	for name, mutate := range cases {
		r := newReceipt()
		mutate(r)
		if err := Sign(priv, r); err != ErrMalformed {
			t.Errorf("%s: Sign = %v, want ErrMalformed", name, err)
		}
		if err := Verify(pub, r); err != ErrMalformed {
			t.Errorf("%s: Verify = %v, want ErrMalformed", name, err)
		}
	}
}

// Both paths must be signable: a donor can serve Xray and VKTP at once, and the
// two are metered differently
func TestBothTransportsSign(t *testing.T) {
	pub, priv := keys(t)
	for _, transport := range []string{TransportXray, TransportVKTP} {
		r := newReceipt()
		r.Transport = transport
		if err := Sign(priv, r); err != nil {
			t.Fatalf("%s: %v", transport, err)
		}
		if err := Verify(pub, r); err != nil {
			t.Errorf("%s did not verify: %v", transport, err)
		}
	}
}
