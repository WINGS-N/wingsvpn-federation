// Package receipt signs and verifies what a client says it actually received.
//
// A node cannot forge a receipt, which is what makes it the only volume number
// worth paying on. Self-reported node counters are fine for enforcing a donor's
// own cap - inflating those only cuts the donor off sooner - but paying on them
// would just be handing out money
package receipt

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"strings"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

var (
	// ErrBadSignature means the receipt was not signed by the client it names
	ErrBadSignature = errors.New("receipt: signature does not verify")
	// ErrMalformed covers a receipt that cannot be meaningful whatever its
	// signature says
	ErrMalformed = errors.New("receipt: malformed")
)

// domain separates these signatures from anything else the client key signs, so
// a receipt can never be replayed as some other message
const domain = "wingsv-fed-receipt-v1\x00"

// The two paths a donated node can carry traffic on
const (
	TransportXray = "xray"
	TransportVKTP = "vktp"
)

// Canonical builds the exact bytes both sides sign and verify.
//
// Fixed-width fields and a domain prefix rather than the wire encoding: protobuf
// serialisation is not canonical, so two encoders can produce different bytes
// for the same message and the signature would break for no reason
func Canonical(r *fedpb.TrafficReceipt) []byte {
	var buf []byte
	buf = append(buf, domain...)
	appendField := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		buf = append(buf, n[:]...)
		buf = append(buf, s...)
	}
	appendNum := func(v uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], v)
		buf = append(buf, n[:]...)
	}
	appendField(r.GetClientId())
	appendField(r.GetNodeId())
	appendField(r.GetTransport())
	appendField(r.GetNonce())
	appendNum(uint64(r.GetWindowStartUnix()))
	appendNum(uint64(r.GetWindowEndUnix()))
	appendNum(r.GetPayloadUpBytes())
	appendNum(r.GetPayloadDownBytes())
	return buf
}

// Sign fills in the signature. Called on the client, which is the only party
// holding the key
func Sign(key ed25519.PrivateKey, r *fedpb.TrafficReceipt) error {
	if err := validate(r); err != nil {
		return err
	}
	r.Signature = ed25519.Sign(key, Canonical(r))
	return nil
}

// Verify checks a receipt against the client's registered public key
func Verify(pub ed25519.PublicKey, r *fedpb.TrafficReceipt) error {
	if err := validate(r); err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize {
		return ErrMalformed
	}
	if !ed25519.Verify(pub, Canonical(r), r.GetSignature()) {
		return ErrBadSignature
	}
	return nil
}

func validate(r *fedpb.TrafficReceipt) error {
	switch {
	case r == nil,
		strings.TrimSpace(r.GetClientId()) == "",
		strings.TrimSpace(r.GetNodeId()) == "",
		strings.TrimSpace(r.GetNonce()) == "":
		return ErrMalformed
	}
	// A receipt that does not name its path cannot be metered against anything
	switch r.GetTransport() {
	case TransportXray, TransportVKTP:
	default:
		return ErrMalformed
	}
	// A window that ends before it starts, or has no duration, cannot describe
	// traffic that happened
	if r.GetWindowEndUnix() <= r.GetWindowStartUnix() {
		return ErrMalformed
	}
	return nil
}
