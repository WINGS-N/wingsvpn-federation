// Package pgstore keeps the head's state in Postgres.
//
// The file stores it replaces were enough for the registry and the allocations,
// which are read whole and written whole. They are not enough for what the
// oracle needs: signals with timestamps, the labels a future model would be
// trained on, and an audit trail that can answer "why was this user cut off".
// Those are time series, and a JSON file rewritten on every change is the wrong
// shape for them.
//
// gorm, and the same version the panel uses, so there is one ORM across the
// project rather than a hand-rolled schema here and gorm there.
package pgstore

import (
	"errors"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Node is the registry, one row per node.
//
// The node itself is JSONB rather than columns: nodes are read as a whole fleet
// and written as a whole fleet, so columns would buy nothing, and every new
// field in the passport would cost a migration on a running head.
type Node struct {
	ID        string `gorm:"primaryKey"`
	Data      []byte `gorm:"type:jsonb;not null"`
	UpdatedAt time.Time
}

// Allocation joins a free user to the nodes serving them. This is the mapping
// the whole privacy design exists to keep in one place, and it is never exposed
// through the donor-facing API.
type Allocation struct {
	UserID    string `gorm:"primaryKey"`
	Data      []byte `gorm:"type:jsonb;not null"`
	UpdatedAt time.Time
}

// Counter is a single guarded row holding the all-time byte total
type Counter struct {
	ID            uint8 `gorm:"primaryKey"`
	LifetimeBytes int64 `gorm:"not null;default:0"`
	// PeriodBaseBytes - отметка на начало текущего периода: трафик за период
	// считается от неё, а не от счётчиков в памяти
	PeriodBaseBytes int64 `gorm:"not null;default:0"`
	UpdatedAt       time.Time
}

// AbuseSignal is the oracle's feature store: raw, append-only and timestamped.
// The rules only need the buckets, but a model has to be trained on something,
// and a signal folded into a counter at write time is gone for good.
type AbuseSignal struct {
	ID         uint64    `gorm:"primaryKey"`
	At         time.Time `gorm:"not null;default:now();index:idx_signal_profile,priority:2,sort:desc;index"`
	ProfileID  string    `gorm:"not null;index:idx_signal_profile,priority:1"`
	NodeID     string    `gorm:"not null"`
	Class      string    `gorm:"not null"`
	Count      int64     `gorm:"not null"`
	WindowSecs int32     `gorm:"not null"`
}

// OracleDecision is every verdict with the scorer that reached it. It answers
// "why was I cut off" a month later, and it doubles as the labelled set a model
// would be trained on.
type OracleDecision struct {
	ID            uint64    `gorm:"primaryKey"`
	At            time.Time `gorm:"not null;default:now();index:idx_decision_subject,priority:2,sort:desc"`
	SubjectID     string    `gorm:"not null;index:idx_decision_subject,priority:1"`
	Verdict       string    `gorm:"not null"`
	Confidence    int32     `gorm:"not null"`
	ScorerVersion string    `gorm:"not null"`
	Reason        string    `gorm:"not null;default:''"`
	Manual        bool      `gorm:"not null;default:false"`
}

// DomainSighting - куда ходил профиль за окно. Хранится сырьём, потому что на
// классах никакую модель не обучишь, там пять бит энтропии и всё.
//
// Живёт ограниченный срок, см. DomainRetention. Мы не ебаная файлопомойка, и
// держать это вечно нельзя ни по смыслу, ни по объёму
type DomainSighting struct {
	ID        uint64    `gorm:"primaryKey"`
	At        time.Time `gorm:"not null;default:now();index:idx_sighting_subject,priority:2,sort:desc;index"`
	SubjectID string    `gorm:"not null;index:idx_sighting_subject,priority:1"`
	ProfileID string    `gorm:"not null"`
	NodeID    string    `gorm:"not null"`
	Domain    string    `gorm:"not null;index"`
	Port      int32     `gorm:"not null;default:0"`
	Count     int64     `gorm:"not null"`
	UpBytes   int64     `gorm:"not null;default:0"`
	DownBytes int64     `gorm:"not null;default:0"`
	// LongLived - сколько соединений жило долго. Пачка коротких запросов и один
	// долгий поток - разное поведение, а по общему счётчику они одинаковые
	LongLived int32 `gorm:"not null;default:0"`
}

// PortSighting - соединения без домена, сведённые по порту. Голый адрес не
// виден в доменах вообще, а торрент и скан живут именно там
type PortSighting struct {
	ID              uint64    `gorm:"primaryKey"`
	At              time.Time `gorm:"not null;default:now();index:idx_port_subject,priority:2,sort:desc;index"`
	SubjectID       string    `gorm:"not null;index:idx_port_subject,priority:1"`
	ProfileID       string    `gorm:"not null"`
	NodeID          string    `gorm:"not null"`
	Port            int32     `gorm:"not null"`
	Count           int64     `gorm:"not null"`
	DistinctTargets int32     `gorm:"not null;default:0"`
	UpBytes         int64     `gorm:"not null;default:0"`
	DownBytes       int64     `gorm:"not null;default:0"`
}

// PrintSighting - отпечаток TLS-стека, с которого работал профиль. Держится
// столько же, сколько домены: это такое же наблюдение, а не вечная картотека
type PrintSighting struct {
	ID        uint64    `gorm:"primaryKey"`
	At        time.Time `gorm:"not null;default:now();index:idx_print_subject,priority:2,sort:desc;index"`
	SubjectID string    `gorm:"not null;index:idx_print_subject,priority:1"`
	ProfileID string    `gorm:"not null"`
	NodeID    string    `gorm:"not null"`
	JA4       string    `gorm:"not null;index"`
	JA3       string    `gorm:"not null;default:''"`
	Count     int64     `gorm:"not null"`
}

// DonorMonth - трафик одного донора за один месяц UTC. Счётчик за период
// обнуляется, и без закрытой строки месяца донору нечего показать за июнь,
// когда наступил июль.
type DonorMonth struct {
	DonorID   string `gorm:"primaryKey"`
	Month     string `gorm:"primaryKey"`
	Bytes     int64  `gorm:"not null;default:0"`
	UpdatedAt time.Time
}

// FleetSetting is one operator decision that applies to the whole fleet, kept as
// a key/value row so a new knob does not cost a migration on a running head.
//
// It lives in the database rather than in a flag on the head because it is a
// decision somebody makes in the panel at three in the morning, not a value that
// gets redeployed.
type FleetSetting struct {
	Key       string `gorm:"primaryKey"`
	Value     string `gorm:"not null;default:''"`
	UpdatedAt time.Time
}

// DB is a gorm handle plus the schema it guarantees
type DB struct {
	gdb *gorm.DB
}

// Open connects and applies the schema.
//
// AutoMigrate runs on every start rather than through a separate migration
// binary: the schema is a handful of tables owned by one process, and a second
// command to run before the first is a deployment step that will be forgotten.
func Open(dsn string) (*DB, error) {
	if dsn == "" {
		return nil, errors.New("pgstore: empty dsn")
	}
	gdb, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		// The head logs its own story; gorm narrating every statement on top of
		// a 1 Hz stat stream would bury it. A missing row is not an error here
		// either - an empty counters table is what a fresh federation looks
		// like, and logging it as a failure trains everyone to ignore the log.
		Logger: logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
			SlowThreshold:             2 * time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
		}),
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, err
	}
	// One process with a handful of goroutines; a large pool would only take
	// connections away from everything else on the cluster
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	if err := gdb.AutoMigrate(&Node{}, &Allocation{}, &Counter{}, &AbuseSignal{}, &OracleDecision{}, &FleetSetting{}, &DonorMonth{}, &EnrollToken{}, &DomainSighting{}, &DeviceSlot{}, &PortSighting{}, &PrintSighting{}, &FeatureSnapshot{}, &TrainedModel{}, &ClientKey{}, &Receipt{}, &VKPeer{}, &EpochRow{}, &EpochLeafRow{}, &NodeBaselineRow{}, &PayoutAddressRow{}, &AnnouncedRateRow{}, &PayoutTxRow{}, &PayoutMarkRow{}, &DonationRow{}, &UpstreamRow{}, &DomainAge{}, &FeedSnapshot{}, &NodeTrafficRow{}); err != nil {
		return nil, err
	}
	return &DB{gdb: gdb}, nil
}

// Close releases the pool
func (d *DB) Close() {
	if sqlDB, err := d.gdb.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// Gorm exposes the handle for the stores
func (d *DB) Gorm() *gorm.DB { return d.gdb }
