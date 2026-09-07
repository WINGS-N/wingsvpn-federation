package pgstore

import (
	"time"

	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	modelpb "wingsnet.org/federation/gen/modelpb"
	"wingsnet.org/federation/internal/head/boost"
	"wingsnet.org/federation/internal/head/labeller"
)

// SnapshotRetention - сколько живёт сырой вектор. Дольше наблюдений нарочно:
// сами домены выкидываются через месяц, а обезличенные числа это уже не история
// посещений, и учиться на них можно спокойно
const SnapshotRetention = 180 * 24 * time.Hour

// FeatureSnapshot - вектор субъекта за окно. Значения лежат протобуфом одним
// куском, а метка отдельной колонкой: размечать удобнее запросом, а не разбором
// блоба по одной строке
type FeatureSnapshot struct {
	ID        uint64    `gorm:"primaryKey"`
	At        time.Time `gorm:"not null;default:now();index"`
	SubjectID string    `gorm:"not null;index:idx_snapshot_subject,priority:1"`
	Version   string    `gorm:"not null;default:''"`
	Payload   []byte    `gorm:"not null"`
	// Label - минус единица пока никто не разметил, ноль чисто, единица
	// злоупотребление. Именно на размеченных и учится модель
	Label int16 `gorm:"not null;default:-1;index"`
	// LabelBy - кто разметил: человек, правила или модель. Нужен, чтобы не учить
	// модель на её же собственных выводах и не уехать в самоподтверждение
	LabelBy string `gorm:"not null;default:''"`
	// LabelWhy - за что обвинили, словами. Держим только у обвинений: по нему
	// человек при проверке сразу видит, модель права или ебанулась, а по голым
	// цифрам этого не понять
	LabelWhy string `gorm:"not null;default:''"`
}

// TrainedModel - обученная модель как она лежит в базе, сжатая
type TrainedModel struct {
	ID        uint64    `gorm:"primaryKey"`
	At        time.Time `gorm:"not null;default:now();index"`
	Version   string    `gorm:"not null"`
	TrainedOn int32     `gorm:"not null"`
	Blob      []byte    `gorm:"not null"`
	// Active - какая из них сейчас судит. Одна активная, остальные история, к
	// которой можно откатиться, когда свежая начнёт нести дичь
	Active bool `gorm:"not null;default:false;index"`
	// Shadow - считает молча, никого не режет
	Shadow bool `gorm:"not null;default:true"`
}

// MLStore копит векторы и хранит модели
type MLStore struct {
	gdb *gorm.DB
}

func NewMLStore(gdb *gorm.DB) *MLStore { return &MLStore{gdb: gdb} }

// PutSnapshot складывает вектор вместе с меткой, если она уже известна
func (m *MLStore) PutSnapshot(
	subjectID string, at time.Time, version string, values map[string]float64, label int16, by string,
) error {
	payload, err := proto.Marshal(&modelpb.FeatureSnapshot{
		SubjectId: subjectID, AtUnix: at.Unix(),
		Values: values, FeatureVersion: version,
	})
	if err != nil {
		return err
	}
	return m.gdb.Create(&FeatureSnapshot{
		At: at, SubjectID: subjectID, Version: version, Payload: payload, Label: label, LabelBy: by,
	}).Error
}

// Labelled поднимает размеченное для обучения
func (m *MLStore) Labelled(version string, limit int) ([]boost.Sample, error) {
	var rows []FeatureSnapshot
	err := m.gdb.Where("label >= 0 AND version = ?", version).
		Order("at DESC").Limit(limit).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]boost.Sample, 0, len(rows))
	for _, r := range rows {
		var snap modelpb.FeatureSnapshot
		if err := proto.Unmarshal(r.Payload, &snap); err != nil {
			continue
		}
		out = append(out, boost.Sample{Values: snap.GetValues(), Label: float64(r.Label)})
	}
	return out, nil
}

// Label ставит метку на всё, что попало в окно вокруг решения
func (m *MLStore) Label(subjectID string, from, to time.Time, label int16, by string) (int64, error) {
	res := m.gdb.Model(&FeatureSnapshot{}).
		Where("subject_id = ? AND at BETWEEN ? AND ?", subjectID, from, to).
		Updates(map[string]any{"label": label, "label_by": by})
	return res.RowsAffected, res.Error
}

// CountLabelled - сколько размеченного накопилось
func (m *MLStore) CountLabelled(version string) (int64, error) {
	var n int64
	err := m.gdb.Model(&FeatureSnapshot{}).Where("label >= 0 AND version = ?", version).Count(&n).Error
	return n, err
}

// SaveModel кладёт модель и делает её активной в тени
func (m *MLStore) SaveModel(model *boost.Model, shadow bool) error {
	blob, err := model.Encode()
	if err != nil {
		return err
	}
	return m.gdb.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&TrainedModel{}).Where("active = ?", true).
			Update("active", false).Error; err != nil {
			return err
		}
		return tx.Create(&TrainedModel{
			At: time.Now().UTC(), Version: model.Version(),
			TrainedOn: int32(model.TrainedOn()), Blob: blob,
			Active: true, Shadow: shadow,
		}).Error
	})
}

// ActiveModel поднимает ту, что судит сейчас. nil, когда модели ещё нет
func (m *MLStore) ActiveModel() (*boost.Model, bool, error) {
	var row TrainedModel
	err := m.gdb.Where("active = ?", true).Order("at DESC").First(&row).Error
	if err != nil {
		return nil, false, nil
	}
	model, err := boost.Decode(row.Blob)
	if err != nil {
		return nil, false, err
	}
	return model, row.Shadow, nil
}

// SweepSnapshots выносит протухшие векторы
func (m *MLStore) SweepSnapshots(now time.Time) (int64, error) {
	// Размеченное не трогаем: это и есть обучающая выборка, ради неё всё
	res := m.gdb.Where("at < ? AND label < 0", now.Add(-SnapshotRetention)).Delete(&FeatureSnapshot{})
	return res.RowsAffected, res.Error
}

// Unlabelled поднимает неразмеченное.
//
// Берём свежее: разметка идёт фоном, и если очередь длиннее, чем разметчик
// успевает жевать, то полезнее свежие наблюдения, а не хвост полугодовой
// давности
func (m *MLStore) Unlabelled(version string, limit int) ([]labeller.Snapshot, error) {
	var rows []FeatureSnapshot
	err := m.gdb.Where("label < 0 AND version = ?", version).
		Order("at DESC").Limit(limit).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]labeller.Snapshot, 0, len(rows))
	for _, r := range rows {
		var snap modelpb.FeatureSnapshot
		if err := proto.Unmarshal(r.Payload, &snap); err != nil {
			continue
		}
		out = append(out, labeller.Snapshot{ID: r.ID, SubjectID: r.SubjectID, Values: snap.GetValues()})
	}
	return out, nil
}

// SetLabel проставляет метку пачке снимков.
//
// Машинная разметка НЕ трогает то, что размечено человеком: человек тут высшая
// инстанция, и затирать его вывод выводом модели значит учить её на её же
// фантазиях
func (m *MLStore) SetLabel(ids []uint64, label int16, by string) error {
	if len(ids) == 0 {
		return nil
	}
	query := m.gdb.Model(&FeatureSnapshot{}).Where("id IN ?", ids)
	if by != "" && by != "human" {
		query = query.Where("label_by = '' OR label_by = ?", by)
	}
	return query.Updates(map[string]any{"label": label, "label_by": by}).Error
}

// SetLabelWhy помечает снимки вместе с объяснением. Человеческую разметку так
// же не трогает, как и SetLabel
func (m *MLStore) SetLabelWhy(reasons map[uint64]string, label int16, by string) error {
	for id, why := range reasons {
		query := m.gdb.Model(&FeatureSnapshot{}).Where("id = ?", id)
		if by != "" && by != "human" {
			query = query.Where("label_by = '' OR label_by = ?", by)
		}
		if err := query.Updates(map[string]any{
			"label": label, "label_by": by, "label_why": why,
		}).Error; err != nil {
			return err
		}
	}
	return nil
}

// LabelPage отдаёт страницу разметки для показа человеку
func (m *MLStore) LabelPage(limit, offset int, accusedOnly bool) ([]LabelRow, int, error) {
	query := m.gdb.Model(&FeatureSnapshot{}).Where("label >= 0")
	if accusedOnly {
		query = query.Where("label = 1")
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []FeatureSnapshot
	if err := query.Order("at DESC").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]LabelRow, 0, len(rows))
	for _, r := range rows {
		var snap modelpb.FeatureSnapshot
		if err := proto.Unmarshal(r.Payload, &snap); err != nil {
			continue
		}
		out = append(out, LabelRow{
			ID: r.ID, AtUnix: r.At.Unix(), SubjectID: r.SubjectID,
			Label: r.Label, LabelBy: r.LabelBy, Why: r.LabelWhy,
			Values: snap.GetValues(),
		})
	}
	return out, int(total), nil
}

// LabelCounts - сколько размечено машиной и сколько подтвердил человек
func (m *MLStore) LabelCounts() (int, int, error) {
	var machine, human int64
	if err := m.gdb.Model(&FeatureSnapshot{}).
		Where("label >= 0 AND label_by <> ? AND label_by <> ''", LabelByHuman).
		Count(&machine).Error; err != nil {
		return 0, 0, err
	}
	if err := m.gdb.Model(&FeatureSnapshot{}).
		Where("label_by = ?", LabelByHuman).Count(&human).Error; err != nil {
		return int(machine), 0, err
	}
	return int(machine), int(human), nil
}

// JudgeLabel записывает приговор человека. Он старше машинного и затирает его
// без разговоров: за тем человек и смотрит
func (m *MLStore) JudgeLabel(id uint64, label int16) error {
	return m.gdb.Model(&FeatureSnapshot{}).Where("id = ?", id).
		Updates(map[string]any{"label": label, "label_by": LabelByHuman}).Error
}

// LabelRow - размеченный снимок в том виде, в каком его показывают человеку.
//
// Свой тип, а не чужой: хранилище не должно знать ни про gRPC-слой, ни про то,
// кто его читает
type LabelRow struct {
	ID        uint64
	AtUnix    int64
	SubjectID string
	Label     int16
	LabelBy   string
	Why       string
	Values    map[string]float64
}

// LabelByHuman - подпись человеческой разметки. Она старше машинной всегда
const LabelByHuman = "human"
