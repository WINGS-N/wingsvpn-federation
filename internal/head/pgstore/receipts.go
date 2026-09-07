package pgstore

import (
	"bytes"
	"errors"
	"time"

	"gorm.io/gorm"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// ClientKey - публичная половина ключа устройства
type ClientKey struct {
	SubjectID string    `gorm:"primaryKey"`
	PublicKey []byte    `gorm:"not null"`
	At        time.Time `gorm:"not null;default:now()"`
	// Rotations - сколько раз ключ менялся. Новый телефон это норма, а вот
	// ключ, который скачет каждый день, сам по себе повод присмотреться
	Rotations int32 `gorm:"not null;default:0"`
}

// Receipt - принятая расписка
type Receipt struct {
	ID        uint64    `gorm:"primaryKey"`
	At        time.Time `gorm:"not null;default:now();index"`
	SubjectID string    `gorm:"not null;index:idx_receipt_subject,priority:1"`
	NodeID    string    `gorm:"not null;index"`
	Transport string    `gorm:"not null;default:''"`
	// Nonce уникален вместе с участником: без этого нода предъявит одну
	// расписку за десяток окон и получит десятикратную оплату
	Nonce           string    `gorm:"not null;uniqueIndex:idx_receipt_nonce,priority:2"`
	SubjectNonce    string    `gorm:"not null;uniqueIndex:idx_receipt_nonce,priority:1"`
	WindowStart     time.Time `gorm:"not null"`
	WindowEnd       time.Time `gorm:"not null"`
	PayloadUpBytes  int64     `gorm:"not null"`
	PayloadDownByte int64     `gorm:"not null"`
}

// ReceiptStore держит ключи и расписки
type ReceiptStore struct {
	gdb *gorm.DB
}

func NewReceiptStore(gdb *gorm.DB) *ReceiptStore { return &ReceiptStore{gdb: gdb} }

// ErrDuplicate - расписку с таким nonce уже приносили
var ErrDuplicate = errors.New("pgstore: receipt already accepted")

// Put запоминает ключ. changed говорит, что он именно сменился
func (r *ReceiptStore) Put(subjectID string, key []byte) (bool, error) {
	var row ClientKey
	err := r.gdb.Where("subject_id = ?", subjectID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, r.gdb.Create(&ClientKey{
			SubjectID: subjectID, PublicKey: key, At: time.Now().UTC(),
		}).Error
	}
	if err != nil {
		return false, err
	}
	if bytes.Equal(row.PublicKey, key) {
		return false, nil
	}
	return true, r.gdb.Model(&ClientKey{}).Where("subject_id = ?", subjectID).
		Updates(map[string]any{
			"public_key": key,
			"at":         time.Now().UTC(),
			"rotations":  gorm.Expr("rotations + 1"),
		}).Error
}

// Get достаёт ключ участника
func (r *ReceiptStore) Get(subjectID string) ([]byte, bool, error) {
	var row ClientKey
	err := r.gdb.Where("subject_id = ?", subjectID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return row.PublicKey, true, nil
}

// Accept сохраняет расписку, отбивая повтор по nonce
func (r *ReceiptStore) Accept(subjectID string, receipt *fedpb.TrafficReceipt) error {
	row := Receipt{
		At:              time.Now().UTC(),
		SubjectID:       subjectID,
		SubjectNonce:    subjectID,
		NodeID:          receipt.GetNodeId(),
		Transport:       receipt.GetTransport(),
		Nonce:           receipt.GetNonce(),
		WindowStart:     time.Unix(receipt.GetWindowStartUnix(), 0).UTC(),
		WindowEnd:       time.Unix(receipt.GetWindowEndUnix(), 0).UTC(),
		PayloadUpBytes:  int64(receipt.GetPayloadUpBytes()),
		PayloadDownByte: int64(receipt.GetPayloadDownBytes()),
	}
	err := r.gdb.Create(&row).Error
	if err != nil && isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

// SignedBytes - сколько участник подтвердил своей подписью за срок
func (r *ReceiptStore) SignedBytes(subjectID string, since time.Time) (uint64, error) {
	var total struct{ Sum int64 }
	err := r.gdb.Model(&Receipt{}).
		Select("COALESCE(SUM(payload_up_bytes + payload_down_byte),0) AS sum").
		Where("subject_id = ? AND window_end >= ?", subjectID, since).
		Scan(&total).Error
	if err != nil {
		return 0, err
	}
	if total.Sum < 0 {
		return 0, nil
	}
	return uint64(total.Sum), nil
}

// LastReceiptAt - когда участник последний раз что-то подписывал. Нулевое
// время означает, что расписок от него нет вообще
func (r *ReceiptStore) LastReceiptAt(subjectID string) (time.Time, error) {
	var row Receipt
	err := r.gdb.Where("subject_id = ?", subjectID).Order("window_end DESC").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return row.WindowEnd, nil
}

// isUniqueViolation ловит повтор, не завися от драйвера: гонять сюда pgconn
// ради одного кода ошибки не хочется
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return contains(text, "duplicate key") || contains(text, "UNIQUE constraint")
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && bytes.Contains([]byte(haystack), []byte(needle))
}

// VKPeer - какой wg-ключ выдан какому профилю на какой ноде.
//
// Без этой связки весь трафик VK TURN висит на голом stream_id, за которым не
// стоит нихуя: ни посчитать, ни сверить с распиской, ни спросить с кого-то
type VKPeer struct {
	PublicKey  string    `gorm:"primaryKey"`
	ClientID   string    `gorm:"not null;index"`
	NodeID     string    `gorm:"not null;index"`
	AllowedIPs string    `gorm:"not null;default:''"`
	At         time.Time `gorm:"not null;default:now()"`
}

// Remember запоминает выданный пир. Один ключ живёт у одного профиля, повторный
// провижн просто обновляет запись
func (r *ReceiptStore) Remember(clientID, nodeID, publicKey, allowedIPs string) error {
	return r.gdb.Where(VKPeer{PublicKey: publicKey}).
		Assign(VKPeer{
			ClientID: clientID, NodeID: nodeID,
			AllowedIPs: allowedIPs, At: time.Now().UTC(),
		}).
		FirstOrCreate(&VKPeer{PublicKey: publicKey}).Error
}

// ProfileOfPeer говорит, чей это ключ. Пустая строка - ничей, такое бывает у
// клиентов донора, которые к федерации отношения не имеют
func (r *ReceiptStore) ProfileOfPeer(publicKey string) (string, bool, error) {
	var row VKPeer
	err := r.gdb.Where("public_key = ?", publicKey).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return row.ClientID, true, nil
}

// SignedByNodeBetween - то же самое, но за закрытое окно. Эпоха обязана считаться
// именно так: с открытым хвостом в неё натечёт трафик, который уже оплачен
// прошлой эпохой, и донор получит за одни байты дважды
func (r *ReceiptStore) SignedByNodeBetween(start, end time.Time) (map[string]uint64, error) {
	var rows []struct {
		NodeID string
		Sum    int64
	}
	err := r.gdb.Model(&Receipt{}).
		Select("node_id, COALESCE(SUM(payload_up_bytes + payload_down_byte),0) AS sum").
		Where("window_end >= ? AND window_end < ?", start, end).Group("node_id").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(rows))
	for _, row := range rows {
		if row.Sum > 0 {
			out[row.NodeID] = uint64(row.Sum)
		}
	}
	return out, nil
}

// SignedByNodeAndSubject - тот же объём, но разложенный по клиентам. Нужен,
// чтобы увидеть ноду, весь трафик которой висит на паре подписей
func (r *ReceiptStore) SignedByNodeAndSubject(start, end time.Time) (map[string]map[string]uint64, error) {
	var rows []struct {
		NodeID    string
		SubjectID string
		Sum       int64
	}
	err := r.gdb.Model(&Receipt{}).
		Select("node_id, subject_id, COALESCE(SUM(payload_up_bytes + payload_down_byte),0) AS sum").
		Where("window_end >= ? AND window_end < ?", start, end).
		Group("node_id, subject_id").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]uint64{}
	for _, row := range rows {
		if row.Sum <= 0 {
			continue
		}
		if out[row.NodeID] == nil {
			out[row.NodeID] = map[string]uint64{}
		}
		out[row.NodeID][row.SubjectID] += uint64(row.Sum)
	}
	return out, nil
}

// SignedByNode - сколько подписано расписками в разрезе нод. В расписке нода
// названа так, как её видит клиент, то есть адресом
func (r *ReceiptStore) SignedByNode(since time.Time) (map[string]uint64, error) {
	var rows []struct {
		NodeID string
		Sum    int64
	}
	err := r.gdb.Model(&Receipt{}).
		Select("node_id, COALESCE(SUM(payload_up_bytes + payload_down_byte),0) AS sum").
		Where("window_end >= ?", since).Group("node_id").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(rows))
	for _, row := range rows {
		if row.Sum > 0 {
			out[row.NodeID] = uint64(row.Sum)
		}
	}
	return out, nil
}

// HasKey - зарегистрировал ли участник ключ. Без него расписки подписывать
// нечем, и спрашивать их с человека бессмысленно
func (r *ReceiptStore) HasKey(subjectID string) (bool, error) {
	var n int64
	err := r.gdb.Model(&ClientKey{}).Where("subject_id = ?", subjectID).Count(&n).Error
	return n > 0, err
}

// KeysOf - ключи пиров человека на конкретной ноде. По ним карантин снимает
// доступ с релея, а не только с ядра
func (r *ReceiptStore) KeysOf(clientID, nodeID string) ([]string, error) {
	var keys []string
	err := r.gdb.Model(&VKPeer{}).Where("client_id = ? AND node_id = ?", clientID, nodeID).
		Pluck("public_key", &keys).Error
	return keys, err
}

// OwnerOf - чей это пир релея. Пусто, если ключ не наш: на релее живут и
// собственные клиенты донора, и приписывать их трафик кому-то мы не вправе
func (r *ReceiptStore) OwnerOf(publicKey string) (string, bool) {
	var row VKPeer
	if err := r.gdb.Where("public_key = ?", publicKey).First(&row).Error; err != nil {
		return "", false
	}
	return row.ClientID, row.ClientID != ""
}

// AddressesOf - адреса пиров человека внутри туннеля. По ним ядро ноды режет
// скорость: у релея своего ограничителя нет
func (r *ReceiptStore) AddressesOf(clientID, nodeID string) ([]string, error) {
	var addresses []string
	err := r.gdb.Model(&VKPeer{}).Where("client_id = ? AND node_id = ? AND allowed_ips <> ''", clientID, nodeID).
		Pluck("allowed_ips", &addresses).Error
	return addresses, err
}
