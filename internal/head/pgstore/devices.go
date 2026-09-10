package pgstore

import (
	"time"

	"gorm.io/gorm"

	"wingsnet.org/federation/internal/head/devices"
)

// DeviceSlot - устройство, за которым закреплён доступ аккаунта
type DeviceSlot struct {
	SubjectID string    `gorm:"primaryKey"`
	HWID      string    `gorm:"primaryKey"`
	DeviceOS  string    `gorm:"not null;default:''"`
	VerOS     string    `gorm:"not null;default:''"`
	Model     string    `gorm:"not null;default:''"`
	FirstSeen time.Time `gorm:"not null;default:now()"`
	LastSeen  time.Time `gorm:"not null;default:now();index"`
}

// DeviceStore - слоты устройств поверх gorm
type DeviceStore struct {
	gdb *gorm.DB
}

func NewDeviceStore(gdb *gorm.DB) *DeviceStore { return &DeviceStore{gdb: gdb} }

func (d *DeviceStore) SlotsOf(subjectID string) ([]devices.Slot, error) {
	var rows []DeviceSlot
	if err := d.gdb.Where("subject_id = ?", subjectID).Order("last_seen ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]devices.Slot, 0, len(rows))
	for _, r := range rows {
		out = append(out, devices.Slot{
			SubjectID: r.SubjectID, HWID: r.HWID,
			DeviceOS: r.DeviceOS, VerOS: r.VerOS, Model: r.Model,
			FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
		})
	}
	return out, nil
}

func (d *DeviceStore) Touch(subjectID, hwid string, at time.Time) error {
	return d.gdb.Model(&DeviceSlot{}).
		Where("subject_id = ? AND hw_id = ?", subjectID, hwid).
		Update("last_seen", at).Error
}

func (d *DeviceStore) Add(slot devices.Slot) error {
	return d.gdb.Create(&DeviceSlot{
		SubjectID: slot.SubjectID, HWID: slot.HWID,
		DeviceOS: slot.DeviceOS, VerOS: slot.VerOS, Model: slot.Model,
		FirstSeen: slot.FirstSeen, LastSeen: slot.LastSeen,
	}).Error
}

func (d *DeviceStore) Drop(subjectID, hwid string) error {
	return d.gdb.Where("subject_id = ? AND hw_id = ?", subjectID, hwid).Delete(&DeviceSlot{}).Error
}
