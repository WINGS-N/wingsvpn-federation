package pgstore

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DomainAge - когда домен зарегистрировали, как нам ответил реестр.
//
// Нулевая дата регистрации означает отказ: зона без RDAP или домена в реестре
// нет. Держим и это, иначе каждый круг разбора будет ломиться в один и тот же
// молчащий реестр
type DomainAge struct {
	Domain       string    `gorm:"primaryKey"`
	RegisteredAt time.Time `gorm:"not null;default:'epoch'"`
	CheckedAt    time.Time `gorm:"not null;default:now();index"`
}

// RDAPStore держит возраст доменов
type RDAPStore struct {
	gdb *gorm.DB
}

func NewRDAPStore(gdb *gorm.DB) *RDAPStore { return &RDAPStore{gdb: gdb} }

// Age отдаёт, что знаем про домен
func (r *RDAPStore) Age(domain string) (time.Time, time.Time, bool) {
	var row DomainAge
	err := r.gdb.Where("domain = ?", domain).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) || err != nil {
		return time.Time{}, time.Time{}, false
	}
	// В базе отказ лежит нулевой датой, а наружу отдаём именно нулевую: слой
	// выше по ней и отличает "не знаем" от "знаем возраст"
	if row.RegisteredAt.Year() <= 1970 {
		return time.Time{}, row.CheckedAt, true
	}
	return row.RegisteredAt, row.CheckedAt, true
}

// Put запоминает дату регистрации
func (r *RDAPStore) Put(domain string, registered, checked time.Time) error {
	return r.upsert(DomainAge{Domain: domain, RegisteredAt: registered.UTC(), CheckedAt: checked.UTC()})
}

// PutMiss запоминает, что ответа нет
func (r *RDAPStore) PutMiss(domain string, checked time.Time) error {
	return r.upsert(DomainAge{Domain: domain, RegisteredAt: time.Unix(0, 0).UTC(), CheckedAt: checked.UTC()})
}

func (r *RDAPStore) upsert(row DomainAge) error {
	return r.gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "domain"}},
		DoUpdates: clause.AssignmentColumns([]string{"registered_at", "checked_at"}),
	}).Create(&row).Error
}
