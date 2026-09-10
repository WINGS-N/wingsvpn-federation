package registry

import (
	"encoding/json"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"wingsnet.org/federation/internal/head/pgstore"
)

// PGStore keeps the registry in Postgres, one row per node
type PGStore struct {
	gdb *gorm.DB
}

// NewPGStore wraps a gorm handle
func NewPGStore(gdb *gorm.DB) *PGStore { return &PGStore{gdb: gdb} }

// Load reads the fleet. An empty table is an empty fleet, not an error
func (s *PGStore) Load() ([]*Node, error) {
	var rows []pgstore.Node
	if err := s.gdb.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*Node, 0, len(rows))
	for _, row := range rows {
		var r persisted
		if err := json.Unmarshal(row.Data, &r); err != nil {
			return nil, err
		}
		out = append(out, r.node())
	}
	return out, nil
}

// Save replaces the fleet in one transaction.
//
// Delete-then-insert rather than upsert: the caller hands over the whole fleet,
// so a node missing from it has been removed, and an upsert would leave it
// behind for ever. The transaction is what keeps a failure from emptying the
// registry - the old rows stand until it commits.
func (s *PGStore) Save(nodes []*Node) error {
	return s.gdb.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&pgstore.Node{}).Error; err != nil {
			return err
		}
		if len(nodes) == 0 {
			return nil
		}
		rows := make([]pgstore.Node, 0, len(nodes))
		for _, n := range nodes {
			raw, err := json.Marshal(newPersisted(n))
			if err != nil {
				return err
			}
			rows = append(rows, pgstore.Node{ID: n.ID, Data: raw})
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			UpdateAll: true,
		}).Create(&rows).Error
	})
}
