package pgstore

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"wingsnet.org/federation/internal/head/upstream"
)

// UpstreamRow - купленная подписка, как она лежит в базе.
//
// Тело сюда же: после выката башка не должна бежать к продавцу за телом всех
// источников разом, это лишний след с нашего адреса и лишний повод для его
// счётчиков
type UpstreamRow struct {
	ID     string `gorm:"primaryKey"`
	Vendor string `gorm:"not null;default:''"`
	URL    string `gorm:"not null"`
	// DeviceID - чем башка представляется продавцу. Один и тот же всегда
	DeviceID   string `gorm:"not null;default:''"`
	MaxClients int    `gorm:"not null;default:0"`
	Enabled    bool   `gorm:"not null;default:false"`
	// Links - последнее прочитанное тело, строками через перевод
	Links     string    `gorm:"not null;default:''"`
	FetchedAt time.Time `gorm:"not null;default:now()"`
	LastError string    `gorm:"not null;default:''"`
}

// UpstreamStore хранит источники
type UpstreamStore struct {
	gdb *gorm.DB
}

func NewUpstreamStore(gdb *gorm.DB) *UpstreamStore { return &UpstreamStore{gdb: gdb} }

// Load поднимает источники
func (u *UpstreamStore) Load() ([]upstream.Source, error) {
	var rows []UpstreamRow
	if err := u.gdb.Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]upstream.Source, 0, len(rows))
	for _, row := range rows {
		out = append(out, upstream.Source{
			ID: row.ID, Vendor: row.Vendor, URL: row.URL,
			DeviceID: row.DeviceID, MaxClients: row.MaxClients, Enabled: row.Enabled,
			Links: splitLines(row.Links), FetchedAt: row.FetchedAt, LastError: row.LastError,
		})
	}
	return out, nil
}

// Save переписывает набор целиком: источник могли снести, и доклеивание к
// старому оставило бы людей на подписке, которую владелец уже убрал
func (u *UpstreamStore) Save(sources []upstream.Source) error {
	return u.gdb.Transaction(func(tx *gorm.DB) error {
		keep := make([]string, 0, len(sources))
		rows := make([]UpstreamRow, 0, len(sources))
		for _, source := range sources {
			keep = append(keep, source.ID)
			rows = append(rows, UpstreamRow{
				ID: source.ID, Vendor: source.Vendor, URL: source.URL,
				DeviceID: source.DeviceID, MaxClients: source.MaxClients, Enabled: source.Enabled,
				Links: joinLines(source.Links), FetchedAt: nowOr(source.FetchedAt), LastError: source.LastError,
			})
		}
		if len(keep) == 0 {
			return tx.Where("1 = 1").Delete(&UpstreamRow{}).Error
		}
		if err := tx.Where("id NOT IN ?", keep).Delete(&UpstreamRow{}).Error; err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"vendor", "url", "device_id", "max_clients", "enabled", "links", "fetched_at", "last_error",
			}),
		}).Create(&rows).Error
	})
}

func nowOr(at time.Time) time.Time {
	if at.IsZero() {
		return time.Now().UTC()
	}
	return at.UTC()
}

// splitLines и joinLines хранят тело одной колонкой: заводить таблицу строк
// ради списка ссылок, который читается и пишется только целиком, незачем
func joinLines(lines []string) string {
	out := ""
	for i, line := range lines {
		if i > 0 {
			out += "\n"
		}
		out += line
	}
	return out
}

func splitLines(value string) []string {
	if value == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(value); i++ {
		if i == len(value) || value[i] == '\n' {
			if line := value[start:i]; line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	return out
}

// enabledKey - где лежит общий рубильник раздачи. Ключ живёт в тех же
// настройках, что и прочие решения оператора: отдельная таблица ради одного
// булева это лишняя миграция на ровном месте
const enabledKey = "upstream.enabled"

// LoadEnabled поднимает рубильник. Нет строки - выключено, и это единственно
// верное умолчание: за чужим сервером Oracle слеп нахуй
func (u *UpstreamStore) LoadEnabled() (bool, error) {
	var row FleetSetting
	err := u.gdb.Where("key = ?", enabledKey).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.Value == "1", nil
}

// SaveEnabled записывает рубильник
func (u *UpstreamStore) SaveEnabled(on bool) error {
	value := "0"
	if on {
		value = "1"
	}
	return u.gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&FleetSetting{Key: enabledKey, Value: value, UpdatedAt: time.Now()}).Error
}
