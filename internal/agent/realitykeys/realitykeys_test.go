package realitykeys

import (
	"os"
	"path/filepath"
	"testing"
)

// stubXray stands in for the binary, echoing the shapes a real one prints
func stubXray(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

const realOutput = `case "$1" in
x25519) echo "PrivateKey: PRIV-VALUE"; echo "Password (PublicKey): PUB-VALUE"; echo "Hash32: HASH" ;;
mldsa65) echo "Seed: SEED-VALUE"; echo "Verify: VERIFY-VALUE" ;;
esac
`

// The labels are not "PublicKey:" but "Password (PublicKey):", and the wording
// has moved between releases, so the parser matches loosely on purpose
func TestParsesRealOutputShape(t *testing.T) {
	pair, err := Generate(stubXray(t, realOutput))
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey != "PRIV-VALUE" {
		t.Errorf("private = %q", pair.PrivateKey)
	}
	if pair.PublicKey != "PUB-VALUE" {
		t.Errorf("public = %q", pair.PublicKey)
	}
	if pair.Mldsa65Seed != "SEED-VALUE" || pair.Mldsa65Verify != "VERIFY-VALUE" {
		t.Errorf("mldsa65 = %q / %q", pair.Mldsa65Seed, pair.Mldsa65Verify)
	}
}

// An older build without the post-quantum subcommand must still produce a usable
// node rather than failing the whole config
func TestMissingMldsa65IsNotFatal(t *testing.T) {
	body := `case "$1" in
x25519) echo "PrivateKey: P"; echo "Password (PublicKey): Q" ;;
*) echo "unknown command" >&2; exit 1 ;;
esac
`
	pair, err := Generate(stubXray(t, body))
	if err != nil {
		t.Fatalf("a build without mldsa65 failed outright: %v", err)
	}
	if pair.PrivateKey == "" || pair.PublicKey == "" {
		t.Error("the x25519 half was lost")
	}
	if pair.Mldsa65Seed != "" {
		t.Error("a seed appeared from a binary that cannot produce one")
	}
}

// Output we do not recognise usually means the wrong binary, and pretending it
// worked would hand Xray an empty key
func TestUnrecognisedOutputFails(t *testing.T) {
	if _, err := Generate(stubXray(t, "echo 'not xray at all'\n")); err != ErrNoOutput {
		t.Errorf("err = %v, want ErrNoOutput", err)
	}
}

func TestMissingBinaryFails(t *testing.T) {
	if _, err := Generate("/nonexistent/xray"); err == nil {
		t.Error("a missing binary was treated as success")
	}
}

// Run against the real fork build when it is around: the stub only proves the
// parser matches what I think the output looks like
func TestAgainstRealBinary(t *testing.T) {
	const real = "/tmp/xraywv/xray"
	if _, err := os.Stat(real); err != nil {
		t.Skip("real xray build not present")
	}
	pair, err := Generate(real)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.PrivateKey) < 40 || len(pair.PublicKey) < 40 {
		t.Errorf("keys look wrong: %q / %q", pair.PrivateKey, pair.PublicKey)
	}
	if pair.Mldsa65Seed == "" || pair.Mldsa65Verify == "" {
		t.Error("the fork build should produce a post-quantum pair")
	}
	// Two runs must not produce the same identity
	second, err := Generate(real)
	if err != nil {
		t.Fatal(err)
	}
	if second.PrivateKey == pair.PrivateKey {
		t.Error("two generations produced the same private key")
	}
}
