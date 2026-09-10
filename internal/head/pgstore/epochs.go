package pgstore

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Эпоха и её листья переживают рестарт башки нарочно: корень в цепочке без
// листьев это мёртвый груз, донор по нему нихуя не склеймит, а пересчитать
// задним числом уже не выйдет - счётчики к тому времени уедут вперёд

// EpochRow - закрытая пачка начислений
type EpochRow struct {
	Number     uint64    `gorm:"primaryKey"`
	StartAt    time.Time `gorm:"not null"`
	EndAt      time.Time `gorm:"not null"`
	Root       []byte    `gorm:"not null"`
	TotalMicro int64     `gorm:"not null"`
	CreatedAt  time.Time `gorm:"not null;default:now()"`
	// PublishedAt и TxRef заполняются, когда корень уехал в цепочку. Пустые
	// означают, что эпоха посчитана, но донорам ещё не за чем приходить
	PublishedAt *time.Time
	TxRef       string `gorm:"not null;default:''"`
}

// EpochLeafRow - строка начисления внутри эпохи
type EpochLeafRow struct {
	Number      uint64 `gorm:"primaryKey"`
	Address     string `gorm:"primaryKey"`
	DonorID     string `gorm:"not null;index"`
	AmountMicro int64  `gorm:"not null"`
}

// EpochStore держит эпохи и их листья
type EpochStore struct {
	gdb *gorm.DB
}

func NewEpochStore(gdb *gorm.DB) *EpochStore { return &EpochStore{gdb: gdb} }

// ErrNoEpoch - такой эпохи нет
var ErrNoEpoch = errors.New("pgstore: no such epoch")

// Save кладёт эпоху вместе с листьями одной транзакцией. Врозь нельзя: эпоха
// без листьев это корень, по которому никто не получит своё
func (e *EpochStore) Save(row EpochRow, leaves []EpochLeafRow) error {
	return e.gdb.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		if err := tx.Where("number = ?", row.Number).Delete(&EpochLeafRow{}).Error; err != nil {
			return err
		}
		if len(leaves) == 0 {
			return nil
		}
		return tx.CreateInBatches(leaves, 200).Error
	})
}

// Get поднимает эпоху по номеру
func (e *EpochStore) Get(number uint64) (EpochRow, error) {
	var row EpochRow
	err := e.gdb.Where("number = ?", number).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return EpochRow{}, ErrNoEpoch
	}
	return row, err
}

// Leaves отдаёт начисления эпохи, из них строится дерево для пруфа
func (e *EpochStore) Leaves(number uint64) ([]EpochLeafRow, error) {
	var rows []EpochLeafRow
	err := e.gdb.Where("number = ?", number).Order("address ASC").Find(&rows).Error
	return rows, err
}

// Last отдаёт последнюю посчитанную эпоху, ноль если их ещё не было
func (e *EpochStore) Last() (uint64, error) {
	var row EpochRow
	err := e.gdb.Order("number DESC").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	return row.Number, err
}

// Next - номер следующей эпохи. Пустая база значит нулевую, а не первую:
// программа в цепочке принимает ровно тот номер, которого ждёт, и начинает с
// нуля
func (e *EpochStore) Next() (uint64, error) {
	var row EpochRow
	err := e.gdb.Order("number DESC").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return row.Number + 1, nil
}

// Unpublished - закрытые эпохи, корень которых так и не уехал в цепочку.
// Публикация могла отбиться о молчащий RPC, а период при этом уже сдвинут:
// без повтора такая эпоха остаётся бумажкой навсегда
func (e *EpochStore) Unpublished(limit int) ([]uint64, error) {
	var rows []EpochRow
	err := e.gdb.Where("published_at IS NULL").Order("number ASC").Limit(limit).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Number)
	}
	return out, nil
}

// MarkPublished отмечает, что корень уехал в цепочку
func (e *EpochStore) MarkPublished(number uint64, at time.Time, ref string) error {
	res := e.gdb.Model(&EpochRow{}).Where("number = ?", number).
		Updates(map[string]any{"published_at": at, "tx_ref": ref})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNoEpoch
	}
	return nil
}

// ForDonor собирает выписку донора: что и в какой эпохе ему начислено
func (e *EpochStore) ForDonor(donorID string, limit int) ([]EpochLeafRow, error) {
	var rows []EpochLeafRow
	err := e.gdb.Where("donor_id = ?", donorID).
		Order("number DESC").Limit(limit).Find(&rows).Error
	return rows, err
}

// NodeBaselineRow - счётчик ноды на конец последней закрытой эпохи.
//
// Агрегатор отдаёт накопленный итог, поэтому период считается приростом. База
// живёт в базе, а не в памяти: после рестарта башки забытая база означает, что
// весь исторический итог ноды предъявят к оплате как один период
type NodeBaselineRow struct {
	NodeID    string    `gorm:"primaryKey"`
	Bytes     int64     `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null;default:now()"`
}

// Baselines поднимает счётчики на конец прошлой эпохи
func (e *EpochStore) Baselines() (map[string]uint64, error) {
	var rows []NodeBaselineRow
	if err := e.gdb.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(rows))
	for _, row := range rows {
		if row.Bytes > 0 {
			out[row.NodeID] = uint64(row.Bytes)
		}
	}
	return out, nil
}

// SaveBaselines запоминает счётчики закрытого периода
func (e *EpochStore) SaveBaselines(next map[string]uint64) error {
	if len(next) == 0 {
		return nil
	}
	rows := make([]NodeBaselineRow, 0, len(next))
	now := time.Now().UTC()
	for nodeID, bytes := range next {
		rows = append(rows, NodeBaselineRow{NodeID: nodeID, Bytes: int64(bytes), UpdatedAt: now})
	}
	return e.gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"bytes", "updated_at"}),
	}).CreateInBatches(rows, 200).Error
}

// AnnouncedRateRow - ставка, объявленная на период вперёд.
//
// Лежит отдельной строкой и не переписывается: пересчитать задним числом значит
// поменять правила после игры, а донор уже повёз трафик под объявленную цену
type AnnouncedRateRow struct {
	PeriodStart time.Time `gorm:"primaryKey"`
	MicroPerGiB int64     `gorm:"not null"`
	// TreasuryMicro и ForecastGiB - из чего ставка получилась. Без них донору
	// нечего ответить на вопрос "почему на этой неделе меньше"
	TreasuryMicro int64     `gorm:"not null;default:0"`
	ForecastGiB   int64     `gorm:"not null;default:0"`
	AnnouncedAt   time.Time `gorm:"not null;default:now()"`
}

// AnnounceRate записывает ставку на период. Повтор не трогает уже объявленное
func (e *EpochStore) AnnounceRate(row AnnouncedRateRow) error {
	return e.gdb.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error
}

// RateFor отдаёт ставку, объявленную на период
func (e *EpochStore) RateFor(periodStart time.Time) (AnnouncedRateRow, bool, error) {
	var row AnnouncedRateRow
	err := e.gdb.Where("period_start = ?", periodStart.UTC()).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AnnouncedRateRow{}, false, nil
	}
	return row, err == nil, err
}

// PayoutAddressRow - куда донору платить. Кошелёк называет сам донор, и это
// единственное, что башка про его деньги знает
type PayoutAddressRow struct {
	DonorID string `gorm:"primaryKey"`
	Address string `gorm:"not null"`
	// TokenAccount - счёт под токен выплат, заведённый башкой. Кошелёк сам
	// токены не держит, деньги идут сюда. Пустой означает, что счёт ещё не
	// открыт и первая же выплата его заведёт
	TokenAccount string    `gorm:"not null;default:''"`
	UpdatedAt    time.Time `gorm:"not null;default:now()"`
}

// SetTokenAccount запоминает счёт под токен. Заводится он один раз на кошелёк,
// потому что открытие стоит ренты
func (e *EpochStore) SetTokenAccount(donorID, account string) error {
	return e.gdb.Model(&PayoutAddressRow{}).Where("donor_id = ?", donorID).
		Updates(map[string]any{"token_account": account, "updated_at": time.Now().UTC()}).Error
}

// PayoutWallets отдаёт кошельки всех доноров: донор -> кошелёк. Нужен обходу
// залогов, который идёт по всем, а не спрашивает по одному
func (e *EpochStore) PayoutWallets() (map[string]string, error) {
	var rows []PayoutAddressRow
	if err := e.gdb.Where("address <> ''").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.DonorID] = row.Address
	}
	return out, nil
}

// TokenAccounts отдаёт готовые счета: кошелёк -> счёт под токен
func (e *EpochStore) TokenAccounts() (map[string]string, error) {
	var rows []PayoutAddressRow
	if err := e.gdb.Where("token_account <> ''").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, row := range rows {
		out[row.Address] = row.TokenAccount
	}
	return out, nil
}

// SetPayoutAddress запоминает кошелёк донора
func (e *EpochStore) SetPayoutAddress(donorID, address string) error {
	return e.gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "donor_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"address", "updated_at"}),
	}).Create(&PayoutAddressRow{
		DonorID: donorID, Address: address, UpdatedAt: time.Now().UTC(),
	}).Error
}

// PayoutAddress отдаёт кошелёк донора
func (e *EpochStore) PayoutAddress(donorID string) (string, bool, error) {
	var row PayoutAddressRow
	err := e.gdb.Where("donor_id = ?", donorID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return row.Address, row.Address != "", nil
}

// PayoutTxRow - выплата конкретному донору, уехавшая в цепочку.
//
// Без неё донор видит "начислено" и ни слова о том, дошли ли деньги: цифра на
// экране без транзакции это обещание, а не выплата
type PayoutTxRow struct {
	Number    uint64    `gorm:"primaryKey"`
	DonorID   string    `gorm:"primaryKey"`
	Address   string    `gorm:"not null"`
	Micro     int64     `gorm:"not null"`
	TxRef     string    `gorm:"not null"`
	PaidAt    time.Time `gorm:"not null;default:now()"`
	CreatedAt time.Time `gorm:"not null;default:now()"`
}

// MarkPaid записывает выплату. Повтор не трогает уже записанное: транзакция
// одна, и переписывать её ссылку незачем
func (e *EpochStore) MarkPaid(row PayoutTxRow) error {
	return e.gdb.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error
}

// PaidFor отдаёт выплаты донора: эпоха -> ссылка на транзакцию
func (e *EpochStore) PaidFor(donorID string) (map[uint64]PayoutTxRow, error) {
	var rows []PayoutTxRow
	if err := e.gdb.Where("donor_id = ?", donorID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[uint64]PayoutTxRow, len(rows))
	for _, row := range rows {
		out[row.Number] = row
	}
	return out, nil
}

// PayoutMarkRow - отметка о том, где кончился последний закрытый период.
//
// Строка ровно одна: без неё после рестарта башки период считался бы от
// сотворения мира, и первая же эпоха оплатила бы всю историю флота разом
type PayoutMarkRow struct {
	ID uint8     `gorm:"primaryKey"`
	At time.Time `gorm:"not null"`
}

// LastPeriodEnd отдаёт конец последнего закрытого периода
func (e *EpochStore) LastPeriodEnd() (time.Time, error) {
	var row PayoutMarkRow
	err := e.gdb.Where("id = 1").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return time.Time{}, nil
	}
	return row.At.UTC(), err
}

// SetPeriodEnd двигает отметку
func (e *EpochStore) SetPeriodEnd(at time.Time) error {
	return e.gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"at"}),
	}).Create(&PayoutMarkRow{ID: 1, At: at.UTC()}).Error
}

// EpochWithLeaf - строка выписки донора: сколько ему начислено в эпохе и уехал
// ли её корень в цепочку
type EpochWithLeaf struct {
	Number      uint64
	StartAt     time.Time
	EndAt       time.Time
	AmountMicro int64
	Root        []byte
	TxRef       string
	PublishedAt *time.Time
}

// StatementFor собирает выписку донора одним запросом: разбирать её по эпохам
// в цикле значит сходить в базу по разу на каждую
func (e *EpochStore) StatementFor(donorID string, limit int) ([]EpochWithLeaf, error) {
	var rows []EpochWithLeaf
	err := e.gdb.Table("epoch_leaf_rows AS l").
		Select("l.number, e.start_at, e.end_at, l.amount_micro, e.root, e.tx_ref, e.published_at").
		Joins("JOIN epoch_rows AS e ON e.number = l.number").
		Where("l.donor_id = ?", donorID).
		Order("l.number DESC").Limit(limit).Scan(&rows).Error
	return rows, err
}

// EpochWithCount - эпоха и сколько в ней листьев
type EpochWithCount struct {
	EpochRow
	Leaves int64
}

// Recent отдаёт последние эпохи владельцу площадки
func (e *EpochStore) Recent(limit int) ([]EpochWithCount, error) {
	var rows []EpochWithCount
	err := e.gdb.Table("epoch_rows AS e").
		Select("e.*, (SELECT COUNT(*) FROM epoch_leaf_rows AS l WHERE l.number = e.number) AS leaves").
		Order("e.number DESC").Limit(limit).Scan(&rows).Error
	return rows, err
}

// DonationRow - занос деньгами в общий котёл. Держим его, потому что доверие,
// купленное за реальные деньги, обязано пережить выкат башки
type DonationRow struct {
	ID        uint64 `gorm:"primaryKey"`
	SubjectID string `gorm:"not null;index"`
	// Reference - подпись транзакции. Уникальна, иначе один занос засчитают
	// дважды и человек получит доверие за чужие деньги
	Reference   string    `gorm:"not null;uniqueIndex"`
	AmountMicro int64     `gorm:"not null"`
	At          time.Time `gorm:"not null"`
}

// Accept записывает занос. Второе значение false, если такой уже был
func (e *EpochStore) Accept(subjectID, reference string, amountMicro uint64, at time.Time) (bool, error) {
	if reference == "" {
		// Без подписи повтор не отловить, поэтому такой занос не храним вовсе
		return true, nil
	}
	row := DonationRow{
		SubjectID: subjectID, Reference: reference,
		AmountMicro: int64(amountMicro), At: at.UTC(),
	}
	res := e.gdb.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

// Donations поднимает заносы за срок: башка держит их в памяти, а после выката
// без этого списка все оплаченные очки доверия испарятся
func (e *EpochStore) Donations(since time.Time) ([]DonationRow, error) {
	var rows []DonationRow
	err := e.gdb.Where("at >= ?", since.UTC()).Order("at ASC").Find(&rows).Error
	return rows, err
}

// DonorByAddress ищет донора по его кошельку: выплата приходит с адресом, а в
// выписке она должна лечь на конкретного человека
func (e *EpochStore) DonorByAddress(address string) (string, bool, error) {
	var row PayoutAddressRow
	err := e.gdb.Where("address = ?", address).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	return row.DonorID, err == nil, err
}
