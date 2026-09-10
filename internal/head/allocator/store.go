package allocator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"wingsnet.org/federation/internal/head/profiles"
)

type persistedProfile struct {
	ID           string `json:"id"`
	NodeID       string `json:"node_id"`
	UUID         string `json:"uuid"`
	Email        string `json:"email"`
	IssuedAtUnix int64  `json:"issued_at_unix"`
}

type persistedAllocation struct {
	UserID          string             `json:"user_id"`
	SubToken        string             `json:"sub_token"`
	Profiles        []persistedProfile `json:"profiles"`
	StickyUntilUnix int64              `json:"sticky_until_unix"`
	UpdatedAtUnix   int64              `json:"updated_at_unix"`
	UsedBytes       uint64             `json:"used_bytes,omitempty"`
	PeriodStartUnix int64              `json:"period_start_unix,omitempty"`
}

// FileStore keeps allocations in one file
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore builds a store rooted at path
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// Load reads the allocations, treating an absent file as no users yet
func (f *FileStore) Load() (map[string]*Allocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rows []persistedAllocation
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	out := make(map[string]*Allocation, len(rows))
	for _, r := range rows {
		out[r.UserID] = r.allocation()
	}
	return out, nil
}

// Save writes at 0600: these rows join a user to the nodes serving them, which
// is the one mapping the whole privacy design exists to keep in one place
func (f *FileStore) Save(state map[string]*Allocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := make([]persistedAllocation, 0, len(state))
	for _, alloc := range state {
		rows = append(rows, newPersistedAllocation(alloc))
	}
	data, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// allocation rebuilds the in-memory shape, shared by every store
func (r persistedAllocation) allocation() *Allocation {
	alloc := &Allocation{
		UserID:      r.UserID,
		SubToken:    r.SubToken,
		Profiles:    make(map[string]profiles.Profile, len(r.Profiles)),
		StickyUntil: time.Unix(r.StickyUntilUnix, 0),
		UpdatedAt:   time.Unix(r.UpdatedAtUnix, 0),
		UsedBytes:   r.UsedBytes,
	}
	if r.PeriodStartUnix > 0 {
		alloc.PeriodStart = time.Unix(r.PeriodStartUnix, 0)
	}
	for _, p := range r.Profiles {
		alloc.Profiles[p.NodeID] = profiles.Profile{
			ID:       p.ID,
			UserID:   r.UserID,
			NodeID:   p.NodeID,
			UUID:     p.UUID,
			Email:    p.Email,
			IssuedAt: time.Unix(p.IssuedAtUnix, 0),
		}
	}
	return alloc
}

// newPersistedAllocation is the other direction
func newPersistedAllocation(alloc *Allocation) persistedAllocation {
	row := persistedAllocation{
		UserID:          alloc.UserID,
		SubToken:        alloc.SubToken,
		StickyUntilUnix: alloc.StickyUntil.Unix(),
		UpdatedAtUnix:   alloc.UpdatedAt.Unix(),
		UsedBytes:       alloc.UsedBytes,
	}
	if !alloc.PeriodStart.IsZero() {
		row.PeriodStartUnix = alloc.PeriodStart.Unix()
	}
	for nodeID, p := range alloc.Profiles {
		row.Profiles = append(row.Profiles, persistedProfile{
			ID:           p.ID,
			NodeID:       nodeID,
			UUID:         p.UUID,
			Email:        p.Email,
			IssuedAtUnix: p.IssuedAt.Unix(),
		})
	}
	return row
}
