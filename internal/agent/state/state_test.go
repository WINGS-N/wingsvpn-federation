package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	want := &State{
		NodeID:       "n1",
		NodeSecret:   "s3cr3t",
		HeadEndpoint: "head.example:9310",
		Fingerprint:  "fp",
		DonorHint:    "donor",
	}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *want {
		t.Errorf("round trip changed the state: %+v", got)
	}
}

// The file holds a secret, so it must never be group or world readable
func TestSaveIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	if err := Save(path, &State{NodeID: "n", NodeSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// It has to be TOML, matching the relay's /etc/wings/vktp/config.toml
func TestFormatIsToml(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")
	if err := Save(path, &State{NodeID: "n1", NodeSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Errorf("state was written as JSON:\n%s", body)
	}
	if !strings.Contains(body, "node-id = 'n1'") && !strings.Contains(body, `node-id = "n1"`) {
		t.Errorf("missing the toml key:\n%s", body)
	}
}

func TestLoadReportsNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "absent.toml")); err != ErrNotEnrolled {
		t.Errorf("missing file: err = %v, want ErrNotEnrolled", err)
	}
	// A file that parses but carries no identity is not an enrollment either
	partial := filepath.Join(dir, "partial.toml")
	if err := os.WriteFile(partial, []byte("head-endpoint = 'x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(partial); err != ErrNotEnrolled {
		t.Errorf("partial file: err = %v, want ErrNotEnrolled", err)
	}
}
