package pgstore

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// FeedSnapshot - последняя удачная загрузка чужого списка.
//
// Имена лежат одним сжатым куском, а НЕ строками по домену: их сотни тысяч, и
// перетряхивать такую таблицу дважды в сутки значит ебать базу без всякой
// пользы. Читаем мы этот список целиком и только на старте
type FeedSnapshot struct {
	FeedID    string    `gorm:"primaryKey"`
	FetchedAt time.Time `gorm:"not null;default:now()"`
	Count     int       `gorm:"not null;default:0"`
	// Domains - имена через перевод строки, сжатые gzip
	Domains []byte `gorm:"type:bytea"`
}

// FeedStore держит снимки чужих списков
type FeedStore struct {
	gdb *gorm.DB
}

func NewFeedStore(gdb *gorm.DB) *FeedStore { return &FeedStore{gdb: gdb} }

// Load поднимает снимок
func (f *FeedStore) Load(feedID string) ([]string, time.Time, error) {
	var row FeedSnapshot
	err := f.gdb.Where("feed_id = ?", feedID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(row.Domains) == 0 {
		return nil, row.FetchedAt, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(row.Domains))
	if err != nil {
		return nil, row.FetchedAt, err
	}
	defer func() { _ = reader.Close() }()
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, row.FetchedAt, err
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n"), row.FetchedAt, nil
}

// Save кладёт снимок
func (f *FeedStore) Save(feedID string, domains []string, fetchedAt time.Time) error {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(strings.Join(domains, "\n"))); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return f.gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "feed_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"fetched_at", "count", "domains"}),
	}).Create(&FeedSnapshot{
		FeedID:    feedID,
		FetchedAt: fetchedAt.UTC(),
		Count:     len(domains),
		Domains:   buf.Bytes(),
	}).Error
}
