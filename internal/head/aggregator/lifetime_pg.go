package aggregator

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"wingsnet.org/federation/internal/head/pgstore"
)

// LifetimePG keeps the all-time counter in Postgres.
//
// One guarded row rather than a file, so the number lives wherever the rest of
// the head's state does. The write never lets it shrink: a head that restarted
// with a stale in-memory value would otherwise publish a smaller total than the
// one visitors have already seen.
type LifetimePG struct {
	gdb *gorm.DB
}

// NewLifetimePG wraps a gorm handle
func NewLifetimePG(gdb *gorm.DB) *LifetimePG { return &LifetimePG{gdb: gdb} }

// LoadPeriodBase читает отметку начала периода
func (l *LifetimePG) LoadPeriodBase() (uint64, error) {
	var row pgstore.Counter
	err := l.gdb.First(&row, 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil || row.PeriodBaseBytes < 0 {
		return 0, err
	}
	return uint64(row.PeriodBaseBytes), nil
}

// SavePeriodBase сохраняет отметку начала периода
func (l *LifetimePG) SavePeriodBase(bytes uint64) error {
	return l.gdb.Model(&pgstore.Counter{}).Where("id = ?", 1).
		Updates(map[string]any{"period_base_bytes": int64(bytes), "updated_at": time.Now()}).Error
}

// Load reads the stored total, treating an empty table as a fresh federation
func (l *LifetimePG) Load() (uint64, error) {
	var row pgstore.Counter
	err := l.gdb.First(&row, 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if row.LifetimeBytes < 0 {
		return 0, nil
	}
	return uint64(row.LifetimeBytes), nil
}

// Save writes the total, never letting it go backwards
func (l *LifetimePG) Save(bytes uint64) error {
	row := pgstore.Counter{ID: 1, LifetimeBytes: int64(bytes), UpdatedAt: time.Now()}
	return l.gdb.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"lifetime_bytes": gorm.Expr("GREATEST(counters.lifetime_bytes, EXCLUDED.lifetime_bytes)"),
			"updated_at":     time.Now(),
		}),
	}).Create(&row).Error
}

// LifetimeStore is what Persist writes through, so the head does not care
// whether the counter lives in a file or in Postgres
type LifetimeStore interface {
	Load() (uint64, error)
	Save(bytes uint64) error
}

// PeriodStore хранит отметку начала периода
type PeriodStore interface {
	LoadPeriodBase() (uint64, error)
	SavePeriodBase(bytes uint64) error
}

// PersistTo keeps a store in step with the aggregator until done is closed.
// Writing on a timer rather than on every sample keeps a 1 Hz stat stream from
// turning into a 1 Hz write
func (a *Aggregator) PersistTo(done <-chan struct{}, store LifetimeStore, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	var last uint64
	for {
		select {
		case <-done:
			// One final write, so an orderly shutdown does not lose the last
			// interval's traffic
			if current := a.Lifetime(); current != last {
				_ = store.Save(current)
			}
			return
		case <-ticker.C:
			current := a.Lifetime()
			if current == last {
				continue
			}
			if err := store.Save(current); err == nil {
				last = current
			}
			if period, ok := store.(PeriodStore); ok {
				_ = period.SavePeriodBase(a.PeriodBase())
			}
		}
	}
}
