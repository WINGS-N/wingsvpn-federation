package pgstore

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// EnrollToken - выданный установщику токен
type EnrollToken struct {
	Token     string `gorm:"primaryKey"`
	DonorID   string `gorm:"not null"`
	ExpiresAt time.Time
	Remaining int64 `gorm:"not null;default:0"`
	CreatedAt time.Time
}

// TokenStore хранит токены в Postgres
type TokenStore struct {
	gdb *gorm.DB
}

// NewTokenStore оборачивает хендл gorm
func NewTokenStore(gdb *gorm.DB) *TokenStore { return &TokenStore{gdb: gdb} }

// Put сохраняет выданный токен
func (t *TokenStore) Put(token, donorID string, expiresAt time.Time, remaining uint32) error {
	return t.gdb.Create(&EnrollToken{
		Token: token, DonorID: donorID, ExpiresAt: expiresAt,
		Remaining: int64(remaining), CreatedAt: time.Now(),
	}).Error
}

// Take списывает одно использование. Условие стоит в самом UPDATE: две ноды,
// зачисляющиеся одновременно, иначе съели бы одно и то же место
func (t *TokenStore) Take(token string, now time.Time) (string, error) {
	res := t.gdb.Model(&EnrollToken{}).
		Where("token = ? AND remaining > 0 AND expires_at > ?", token, now).
		Update("remaining", gorm.Expr("remaining - 1"))
	if res.Error != nil {
		return "", res.Error
	}
	if res.RowsAffected == 0 {
		return "", errors.New("tokens: rejected")
	}
	var row EnrollToken
	if err := t.gdb.First(&row, "token = ?", token).Error; err != nil {
		return "", err
	}
	return row.DonorID, nil
}

// Left - сколько зачислений ещё разрешает токен
func (t *TokenStore) Left(token string, now time.Time) uint32 {
	var row EnrollToken
	if err := t.gdb.First(&row, "token = ? AND expires_at > ?", token, now).Error; err != nil {
		return 0
	}
	if row.Remaining < 0 {
		return 0
	}
	return uint32(row.Remaining)
}
