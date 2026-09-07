package aggregator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// LifetimeFile persists the all-time byte counter.
//
// It lives in its own tiny file rather than in the registry: the registry is
// rewritten whenever a node changes, while this is a single number touched once
// a minute, and a public counter that silently reset to zero on every restart
// would understate the donors' work every time the head is deployed.
type LifetimeFile struct {
	path string
}

// NewLifetimeFile points the store at a path
func NewLifetimeFile(path string) *LifetimeFile { return &LifetimeFile{path: path} }

type lifetimeDoc struct {
	Bytes uint64 `json:"lifetime_bytes"`
}

// Load reads the stored total. A missing file is not an error - it is the first
// run, and the counter starts where it should
func (f *LifetimeFile) Load() (uint64, error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var doc lifetimeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, err
	}
	return doc.Bytes, nil
}

// Save writes the total through a temporary file, so a head killed mid-write
// leaves the previous number rather than a truncated one
func (f *LifetimeFile) Save(bytes uint64) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(lifetimeDoc{Bytes: bytes})
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// Persist keeps the file in step with the aggregator until done is closed
func (a *Aggregator) Persist(done <-chan struct{}, store *LifetimeFile, every time.Duration) {
	a.PersistTo(done, store, every)
}
