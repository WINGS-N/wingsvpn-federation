package pgstore

import (
	"context"
	"time"

	"gorm.io/gorm"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// DomainRetention - сколько живёт сырое наблюдение. Месяца хватает и на разбор
// жалобы, и на обучение, а вечно держать чужие домены мы не будем: это не
// файлопомойка, и лишний срок хранения - это только лишний риск
const DomainRetention = 30 * 24 * time.Hour

// sweepEvery - как часто выносится протухшее
const sweepEvery = time.Hour

// DomainStore пишет, куда ходили профили, и сам же за собой убирает
type DomainStore struct {
	gdb *gorm.DB
	// resolve превращает профиль в участника. Нода про людей не знает ничего и
	// шлёт только идентификатор профиля
	resolve func(profileID string) (string, bool)
}

func NewDomainStore(gdb *gorm.DB, resolve func(string) (string, bool)) *DomainStore {
	return &DomainStore{gdb: gdb, resolve: resolve}
}

// Record складывает окно с одной ноды
func (d *DomainStore) Record(batch *fedpb.DomainBatch, nodeID string) error {
	if batch == nil || len(batch.GetSamples()) == 0 {
		return nil
	}
	rows := make([]DomainSighting, 0, len(batch.GetSamples()))
	for _, sample := range batch.GetSamples() {
		subject := ""
		if d.resolve != nil {
			if owner, ok := d.resolve(sample.GetProfileId()); ok {
				subject = owner
			}
		}
		at := time.Unix(sample.GetLastSeenUnix(), 0).UTC()
		if sample.GetLastSeenUnix() == 0 {
			at = time.Now().UTC()
		}
		rows = append(rows, DomainSighting{
			At:        at,
			SubjectID: subject,
			ProfileID: sample.GetProfileId(),
			NodeID:    nodeID,
			Domain:    sample.GetDomain(),
			Port:      int32(sample.GetPort()),
			Count:     int64(sample.GetCount()),
			UpBytes:   int64(sample.GetUpBytes()),
			DownBytes: int64(sample.GetDownBytes()),
			LongLived: int32(sample.GetLongLived()),
		})
	}
	if len(rows) > 0 {
		if err := d.gdb.CreateInBatches(rows, 200).Error; err != nil {
			return err
		}
	}
	if err := d.recordPrints(batch, nodeID); err != nil {
		return err
	}
	return d.recordPorts(batch, nodeID)
}

// recordPrints складывает отпечатки TLS-стеков
func (d *DomainStore) recordPrints(batch *fedpb.DomainBatch, nodeID string) error {
	if len(batch.GetPrints()) == 0 {
		return nil
	}
	rows := make([]PrintSighting, 0, len(batch.GetPrints()))
	for _, sample := range batch.GetPrints() {
		subject := ""
		if d.resolve != nil {
			if owner, ok := d.resolve(sample.GetProfileId()); ok {
				subject = owner
			}
		}
		at := time.Unix(sample.GetLastSeenUnix(), 0).UTC()
		if sample.GetLastSeenUnix() == 0 {
			at = time.Now().UTC()
		}
		rows = append(rows, PrintSighting{
			At:        at,
			SubjectID: subject,
			ProfileID: sample.GetProfileId(),
			NodeID:    nodeID,
			JA4:       sample.GetJa4(),
			JA3:       sample.GetJa3(),
			Count:     int64(sample.GetCount()),
		})
	}
	return d.gdb.CreateInBatches(rows, 200).Error
}

// PrintCount - один отпечаток субъекта, свёрнутый за срок
type PrintCount struct {
	JA4      string
	JA3      string
	Hits     int64
	LastSeen time.Time
}

// Prints - какими стеками субъект работал за срок, самые частые первыми
func (d *DomainStore) Prints(subjectID string, since time.Time, limit int) ([]PrintCount, error) {
	var out []PrintCount
	err := d.gdb.Model(&PrintSighting{}).
		Select("ja4, MAX(ja3) AS ja3, SUM(count) AS hits, MAX(at) AS last_seen").
		Where("subject_id = ? AND at >= ?", subjectID, since).
		Group("ja4").Order("hits DESC").Limit(limit).Scan(&out).Error
	return out, err
}

// PrintsSince поднимает свежие отпечатки для разбора
func (d *DomainStore) PrintsSince(mark time.Time, limit int) ([]PrintSighting, error) {
	var rows []PrintSighting
	err := d.gdb.Where("at > ? AND subject_id <> ''", mark).
		Order("at ASC").Limit(limit).Find(&rows).Error
	return rows, err
}

// recordPorts складывает соединения, у которых домена не было
func (d *DomainStore) recordPorts(batch *fedpb.DomainBatch, nodeID string) error {
	if len(batch.GetPorts()) == 0 {
		return nil
	}
	now := time.Now().UTC()
	rows := make([]PortSighting, 0, len(batch.GetPorts()))
	for _, sample := range batch.GetPorts() {
		subject := ""
		if d.resolve != nil {
			if owner, ok := d.resolve(sample.GetProfileId()); ok {
				subject = owner
			}
		}
		rows = append(rows, PortSighting{
			At:        now,
			SubjectID: subject,
			ProfileID: sample.GetProfileId(),
			NodeID:    nodeID,
			Port:      int32(sample.GetPort()),
			Count:     int64(sample.GetCount()),

			DistinctTargets: int32(sample.GetDistinctTargets()),
			UpBytes:         int64(sample.GetUpBytes()),
			DownBytes:       int64(sample.GetDownBytes()),
		})
	}
	return d.gdb.CreateInBatches(rows, 200).Error
}

// PortsSince поднимает свежие соединения без домена
func (d *DomainStore) PortsSince(mark time.Time, limit int) ([]PortSighting, error) {
	var rows []PortSighting
	err := d.gdb.Where("at > ? AND subject_id <> ''", mark).
		Order("at ASC").Limit(limit).Find(&rows).Error
	return rows, err
}

// TopDomains - куда участник ходил чаще всего за срок
func (d *DomainStore) TopDomains(subjectID string, since time.Time, limit int) ([]DomainCount, error) {
	rows, _, err := d.TopDomainsPage(subjectID, since, limit, 0)
	return rows, err
}

// TopDomainsPage отдаёт страницу и общее число доменов. Хвост у активного
// участника уходит в тысячи строк, и вываливать его разом некуда
func (d *DomainStore) TopDomainsPage(subjectID string, since time.Time, limit, offset int) ([]DomainCount, int64, error) {
	var total int64
	err := d.gdb.Model(&DomainSighting{}).
		Where("subject_id = ? AND at >= ?", subjectID, since).
		Distinct("domain").Count(&total).Error
	if err != nil {
		return nil, 0, err
	}
	var out []DomainCount
	err = d.gdb.Model(&DomainSighting{}).
		Select("domain, SUM(count) AS hits, SUM(up_bytes) AS up_bytes, SUM(down_bytes) AS down_bytes, MAX(at) AS last_seen").
		Where("subject_id = ? AND at >= ?", subjectID, since).
		Group("domain").Order("hits DESC").Limit(limit).Offset(offset).Scan(&out).Error
	return out, total, err
}

// DomainCount - свёрнутая строка для показа в панели
type DomainCount struct {
	Domain    string
	Hits      int64
	UpBytes   int64
	DownBytes int64
	LastSeen  time.Time
}

// Sweep выносит протухшее. Возвращает, сколько строк ушло
func (d *DomainStore) Sweep(now time.Time) (int64, error) {
	cutoff := now.Add(-DomainRetention)
	res := d.gdb.Where("at < ?", cutoff).Delete(&DomainSighting{})
	if res.Error != nil {
		return res.RowsAffected, res.Error
	}
	ports := d.gdb.Where("at < ?", cutoff).Delete(&PortSighting{})
	if ports.Error != nil {
		return res.RowsAffected + ports.RowsAffected, ports.Error
	}
	prints := d.gdb.Where("at < ?", cutoff).Delete(&PrintSighting{})
	return res.RowsAffected + ports.RowsAffected + prints.RowsAffected, prints.Error
}

// RunSweeper убирает по расписанию, пока жив ctx. Чистка на записи не годится,
// иначе один заход собирает на себя чужую уборку и тормозит приём
func (d *DomainStore) RunSweeper(ctx context.Context, log func(string, ...any)) {
	ticker := time.NewTicker(sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed, err := d.Sweep(time.Now().UTC())
			if err != nil && log != nil {
				log("pgstore: domain sweep failed: %v", err)
				continue
			}
			if removed > 0 && log != nil {
				log("pgstore: swept %d expired observations", removed)
			}
		}
	}
}

// Since поднимает наблюдения, пришедшие после отметки. Разбор идёт по свежему
// куску, иначе одно и то же обвинение улетало бы наверх на каждом круге
func (d *DomainStore) Since(mark time.Time, limit int) ([]DomainSighting, error) {
	var rows []DomainSighting
	err := d.gdb.Where("at > ? AND subject_id <> ''", mark).
		Order("at ASC").Limit(limit).Find(&rows).Error
	return rows, err
}

// HourlyRow - сколько обращений субъект сделал в один час суток и в скольких
// сутках этот час вообще был занят
type HourlyRow struct {
	SubjectID string
	Hour      int
	Hits      int64
	Days      int64
}

// HourlyLoad сводит наблюдения по часам суток. Считается в базе, а не в башке:
// вытаскивать недельный сырец в память ради двух десятков чисел на человека -
// это чистая дурость
func (d *DomainStore) HourlyLoad(since time.Time) ([]HourlyRow, error) {
	var out []HourlyRow
	err := d.gdb.Model(&DomainSighting{}).
		Select("subject_id, EXTRACT(HOUR FROM at)::int AS hour, SUM(count) AS hits, "+
			"COUNT(DISTINCT DATE_TRUNC('day', at)) AS days").
		Where("at >= ? AND subject_id <> ''", since).
		Group("subject_id, hour").Scan(&out).Error
	return out, err
}

// ReviewDomains отдаёт походы субъекта в том виде, в каком их читает разбор
// обвинений
func (d *DomainStore) ReviewDomains(subjectID string, since time.Time, limit int) ([]ReviewDomain, error) {
	rows, err := d.TopDomains(subjectID, since, limit)
	if err != nil {
		return nil, err
	}
	out := make([]ReviewDomain, 0, len(rows))
	for _, row := range rows {
		out = append(out, ReviewDomain{
			Name: row.Domain, Hits: row.Hits,
			Bytes: uint64(row.UpBytes + row.DownBytes),
		})
	}
	return out, nil
}

// ReviewDomain - домен для разбора обвинения: имя, сколько раз и сколько байт
type ReviewDomain struct {
	Name  string
	Hits  int64
	Bytes uint64
}
