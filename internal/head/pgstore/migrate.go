package pgstore

import (
	"context"
	"fmt"
	"log"
)

// Seeder is one piece of state that can be copied from the files into Postgres
type Seeder struct {
	// Name is what gets logged
	Name string
	// Empty reports whether Postgres already holds this state. A non-empty table
	// is never touched: the files are a starting point, not a source of truth
	// that keeps overwriting the database on every boot
	Empty func(ctx context.Context) (bool, error)
	// Copy moves whatever the files hold into Postgres, reporting whether there
	// was anything to move. Empty files are the normal case on a fresh install,
	// and announcing a copy that did not happen makes the log lie.
	Copy func() (bool, error)
}

// SeedFromFiles fills empty tables from the old JSON files, once.
//
// It exists so switching a running head onto Postgres is a redeploy rather than
// a manual export. It is deliberately one-way and only into empty tables: if the
// database already has rows, the files are stale by definition and copying them
// over would undo whatever happened since the switch.
func SeedFromFiles(ctx context.Context, seeders ...Seeder) error {
	for _, s := range seeders {
		empty, err := s.Empty(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		if !empty {
			continue
		}
		copied, err := s.Copy()
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		if copied {
			log.Printf("pgstore: seeded %s from the on-disk state", s.Name)
		}
	}
	return nil
}

// TableEmpty is the usual Empty implementation. It takes a model rather than a
// table name so the name comes from gorm and cannot drift from the schema.
func (d *DB) TableEmpty(model any) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		var count int64
		// Limited to one: whether there is anything is the whole question, and
		// counting a growing signal table would get slower every week
		err := d.gdb.WithContext(ctx).Model(model).Limit(1).Count(&count).Error
		return count == 0, err
	}
}
