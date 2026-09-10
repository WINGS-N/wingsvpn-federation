package pgstore

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// FleetStore reads and writes the operator's fleet-wide choices.
type FleetStore struct {
	gdb *gorm.DB
}

// NewFleetStore wraps a gorm handle
func NewFleetStore(gdb *gorm.DB) *FleetStore { return &FleetStore{gdb: gdb} }

// Load returns every setting. A missing key is simply absent from the map, and
// the caller supplies its own default - the head has to boot with no database
// rows at all on the first run.
func (f *FleetStore) Load() (map[string]string, error) {
	var rows []FleetSetting
	if err := f.gdb.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Key] = r.Value
	}
	return out, nil
}

// Save writes the given keys, leaving everything else alone. Partial on purpose:
// the panel sends the section somebody edited, not the whole world.
func (f *FleetStore) Save(values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	rows := make([]FleetSetting, 0, len(values))
	for k, v := range values {
		rows = append(rows, FleetSetting{Key: k, Value: v, UpdatedAt: time.Now()})
	}
	return f.gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&rows).Error
}

// Get is Load for one key
func (f *FleetStore) Get(key string) (string, error) {
	var row FleetSetting
	err := f.gdb.First(&row, "key = ?", key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	return row.Value, err
}
