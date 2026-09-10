package pgstore

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// NodeTrafficRow - накопленный трафик одной ноды, как его видит держащая её
// реплика.
//
// Сессия агента висит на одном поде, поэтому в памяти у реплики только её ноды.
// Строка тут - способ репликам увидеть флот целиком, не отбирая у себя HA
type NodeTrafficRow struct {
	NodeID     string `gorm:"primaryKey"`
	DonorID    string `gorm:"not null;default:''"`
	UpBytes    int64  `gorm:"not null;default:0"`
	DownBytes  int64  `gorm:"not null;default:0"`
	ProbeBytes int64  `gorm:"not null;default:0"`
	Sessions   int32  `gorm:"not null;default:0"`
	Streams    int32  `gorm:"not null;default:0"`
	UpRate     float64
	DownRate   float64
	SeenAt     time.Time `gorm:"not null;default:now()"`
}

// NodeTrafficStore публикует и читает общий срез по нодам
type NodeTrafficStore struct {
	gdb *gorm.DB
}

// NewNodeTrafficStore оборачивает хендл gorm
func NewNodeTrafficStore(gdb *gorm.DB) *NodeTrafficStore { return &NodeTrafficStore{gdb: gdb} }

// PublishNodes кладёт срез своих нод. Счётчики только растут: реплика, поднятая
// с пустой памятью, иначе стёрла бы уже показанные цифры
func (s *NodeTrafficStore) PublishNodes(rows []NodeTrafficRow) error {
	if len(rows) == 0 {
		return nil
	}
	// Побеждает свежая запись, а не большая: счётчики ноды кумулятивны с её
	// собственного старта, и после её перезапуска честный ноль обязан перебить
	// накопленное старьё
	return s.gdb.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "node_id"}},
		Where: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "node_traffic_rows.seen_at <= EXCLUDED.seen_at"},
		}},
		DoUpdates: clause.Assignments(map[string]any{
			"donor_id":    gorm.Expr("EXCLUDED.donor_id"),
			"up_bytes":    gorm.Expr("EXCLUDED.up_bytes"),
			"down_bytes":  gorm.Expr("EXCLUDED.down_bytes"),
			"probe_bytes": gorm.Expr("EXCLUDED.probe_bytes"),
			"sessions":    gorm.Expr("EXCLUDED.sessions"),
			"streams":     gorm.Expr("EXCLUDED.streams"),
			"up_rate":     gorm.Expr("EXCLUDED.up_rate"),
			"down_rate":   gorm.Expr("EXCLUDED.down_rate"),
			"seen_at":     gorm.Expr("EXCLUDED.seen_at"),
		}),
	}).Create(&rows).Error
}

// LoadNodes отдаёт весь флот, включая ноды соседних реплик
func (s *NodeTrafficStore) LoadNodes() ([]NodeTrafficRow, error) {
	var rows []NodeTrafficRow
	err := s.gdb.Find(&rows).Error
	return rows, err
}
