// Package state persists what the node learned when it enrolled
package state

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// Paths follow the fleet convention /etc/wings/<component>, matching the relay's
// /etc/wings/vktp
const (
	// DefaultPath is where the enrolled identity lives
	DefaultPath = "/etc/wings/federation/node.toml"
	// StateDir holds mutable runtime state that survives a restart
	StateDir = "/var/lib/wings/federation"
	// LogDir holds what the supervised children write
	LogDir = "/var/log/wings/federation"
)

// State is the node's identity and where to reach the head. TOML to match the
// rest of the fleet, where the relay reads /etc/wings/vktp/config.toml
type State struct {
	NodeID string `toml:"node-id"`
	// NodeSecret authorises this node at the app layer; FleetSecret only keys the
	// transport and is shared by every donor, so it authenticates nobody
	NodeSecret   string `toml:"node-secret"`
	FleetSecret  string `toml:"fleet-secret"`
	HeadEndpoint string `toml:"head-endpoint"`
	Fingerprint  string `toml:"fingerprint"`
	DonorHint    string `toml:"donor-hint,omitempty"`
}

// ErrNotEnrolled means the node has no identity yet
var ErrNotEnrolled = errors.New("state: node is not enrolled")

// Load reads the stored identity
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := toml.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.NodeID == "" || s.NodeSecret == "" {
		return nil, ErrNotEnrolled
	}
	return &s, nil
}

// Save writes the identity at 0600; it is key material, not configuration
func Save(path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := toml.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
