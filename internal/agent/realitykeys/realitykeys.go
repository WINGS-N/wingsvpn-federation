// Package realitykeys generates the node's REALITY identity.
//
// Generated on the node and never sent anywhere: only the public halves travel,
// in ConfigAck. A central private key would mean one compromised donor burns the
// inbound identity of the whole fleet
package realitykeys

import (
	"errors"
	"os/exec"
	"strings"
)

// Pair is one REALITY identity. Private halves stay on disk here
type Pair struct {
	PrivateKey string
	PublicKey  string
	// Mldsa65Seed and Mldsa65Verify are the post-quantum authentication half.
	// Empty when the build does not support it, which is not fatal
	Mldsa65Seed   string
	Mldsa65Verify string
}

// ErrNoOutput means the binary answered in a shape we do not recognise, which
// usually means it is the wrong binary rather than a broken one
var ErrNoOutput = errors.New("realitykeys: unexpected output from xray")

// Generate runs the xray binary to mint a fresh identity. It needs the binary on
// disk already, so binfetch has to run first
func Generate(xrayBinary string) (Pair, error) {
	priv, pub, err := x25519(xrayBinary)
	if err != nil {
		return Pair{}, err
	}
	pair := Pair{PrivateKey: priv, PublicKey: pub}
	// Post-quantum auth is a bonus: an older build without the subcommand still
	// yields a usable node
	if seed, verify, err := mldsa65(xrayBinary); err == nil {
		pair.Mldsa65Seed, pair.Mldsa65Verify = seed, verify
	}
	return pair, nil
}

func x25519(binary string) (private, public string, err error) {
	out, err := exec.Command(binary, "x25519").CombinedOutput()
	if err != nil {
		return "", "", err
	}
	private = fieldAfter(string(out), "private")
	public = fieldAfter(string(out), "public")
	if private == "" || public == "" {
		return "", "", ErrNoOutput
	}
	return private, public, nil
}

func mldsa65(binary string) (seed, verify string, err error) {
	out, err := exec.Command(binary, "mldsa65").CombinedOutput()
	if err != nil {
		return "", "", err
	}
	seed = fieldAfter(string(out), "seed")
	verify = fieldAfter(string(out), "verify")
	if seed == "" || verify == "" {
		return "", "", ErrNoOutput
	}
	return seed, verify, nil
}

// fieldAfter pulls the value from a "Label: value" line, matching on a substring
// because the exact wording has changed between releases
func fieldAfter(out, label string) string {
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, label) {
			continue
		}
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		if value := strings.TrimSpace(line[idx+1:]); value != "" {
			return value
		}
	}
	return ""
}
