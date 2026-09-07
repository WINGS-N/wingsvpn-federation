package allocator

import (
	"encoding/json"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"wingsnet.org/federation/internal/head/pgstore"
)

// PGStore keeps allocations in Postgres, one row per user.
//
// This table joins a free user to the nodes serving them, which is exactly the
// mapping the privacy design keeps in a single place. It stays here and is never
// exposed through the donor-facing API.
type PGStore struct {
	gdb *gorm.DB
}

// NewPGStore wraps a gorm handle
func NewPGStore(gdb *gorm.DB) *PGStore { return &PGStore{gdb: gdb} }

// Load reads every allocation
func (s *PGStore) Load() (map[string]*Allocation, error) {
	var rows []pgstore.Allocation
	if err := s.gdb.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]*Allocation, len(rows))
	for _, row := range rows {
		var r persistedAllocation
		if err := json.Unmarshal(row.Data, &r); err != nil {
			return nil, err
		}
		out[r.UserID] = r.allocation()
	}
	return out, nil
}

// Save replaces the whole set in one transaction, for the same reason the
// registry does: a user missing from the map has been revoked, and an upsert
// would keep serving them
func (s *PGStore) Save(state map[string]*Allocation) error {
	return s.gdb.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&pgstore.Allocation{}).Error; err != nil {
			return err
		}
		if len(state) == 0 {
			return nil
		}
		rows := make([]pgstore.Allocation, 0, len(state))
		for userID, alloc := range state {
			raw, err := json.Marshal(newPersistedAllocation(alloc))
			if err != nil {
				return err
			}
			rows = append(rows, pgstore.Allocation{UserID: userID, Data: raw})
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			UpdateAll: true,
		}).Create(&rows).Error
	})
}
