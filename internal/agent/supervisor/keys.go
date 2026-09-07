package supervisor

import (
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"

	"wingsnet.org/federation/internal/agent/realitykeys"
)

// The identity is minted once and kept. Regenerating it would hand every client
// already holding the old public key a server that no longer matches
type storedKeys struct {
	PrivateKey    string `toml:"reality-private-key"`
	PublicKey     string `toml:"reality-public-key"`
	Mldsa65Seed   string `toml:"mldsa65-seed"`
	Mldsa65Verify string `toml:"mldsa65-verify"`
}

func loadKeys(path string) (realitykeys.Pair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return realitykeys.Pair{}, err
	}
	var k storedKeys
	if err := toml.Unmarshal(data, &k); err != nil {
		return realitykeys.Pair{}, err
	}
	return realitykeys.Pair{
		PrivateKey:    k.PrivateKey,
		PublicKey:     k.PublicKey,
		Mldsa65Seed:   k.Mldsa65Seed,
		Mldsa65Verify: k.Mldsa65Verify,
	}, nil
}

// saveKeys writes at 0600: this is the node's inbound identity, and a readable
// copy hands anybody the ability to impersonate it
func saveKeys(path string, p realitykeys.Pair) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := toml.Marshal(storedKeys{
		PrivateKey:    p.PrivateKey,
		PublicKey:     p.PublicKey,
		Mldsa65Seed:   p.Mldsa65Seed,
		Mldsa65Verify: p.Mldsa65Verify,
	})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// The applied config version survives an agent restart so a plain
// systemctl restart does not look like a fresh node and earn a config push,
// which would restart Xray and drop every live connection
type storedApplied struct {
	ConfigVersion uint64 `toml:"config-version"`
	// Schema - ревизия генератора конфига в самом агенте. Номер версии от башки
	// про неё ничего не знает, поэтому без этого поля обновление агента, которое
	// меняет собираемый конфиг, не доезжает до ноды никогда: башка видит ту же
	// версию и не шлёт пуш, а перегенерить самому агенту нечего - конфига он
	// не хранит
	Schema int `toml:"schema"`
}

func loadAppliedVersion(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var a storedApplied
	if err := toml.Unmarshal(data, &a); err != nil {
		return 0
	}
	if a.Schema != configSchema {
		return 0
	}
	return a.ConfigVersion
}

func saveAppliedVersion(path string, version uint64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := toml.Marshal(storedApplied{ConfigVersion: version, Schema: configSchema})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
