package donations

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"wingsnet.org/federation/internal/head/pgstore"
)

// PGStore держит помесячные строки в Postgres
type PGStore struct {
	gdb *gorm.DB
}

// NewPGStore оборачивает хендл gorm
func NewPGStore(gdb *gorm.DB) *PGStore { return &PGStore{gdb: gdb} }

// Add прибавляет к строке месяца. Сложение делает база: две башки,
// сбросившие одновременно, иначе потеряли бы байты
func (p *PGStore) Add(donorID, month string, bytes uint64) error {
	row := pgstore.DonorMonth{DonorID: donorID, Month: month, Bytes: int64(bytes), UpdatedAt: time.Now()}
	return p.gdb.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "donor_id"}, {Name: "month"}},
		DoUpdates: clause.Assignments(map[string]any{
			"bytes":      gorm.Expr("donor_months.bytes + EXCLUDED.bytes"),
			"updated_at": time.Now(),
		}),
	}).Create(&row).Error
}

// History возвращает свежие месяцы донора первыми
func (p *PGStore) History(donorID string, months int) ([]Entry, error) {
	var rows []pgstore.DonorMonth
	err := p.gdb.Where("donor_id = ?", donorID).
		Order("month DESC").Limit(months).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(rows))
	for _, r := range rows {
		if r.Bytes < 0 {
			continue
		}
		out = append(out, Entry{Month: r.Month, Bytes: uint64(r.Bytes)})
	}
	return out, nil
}
