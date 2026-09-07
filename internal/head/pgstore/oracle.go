package pgstore

import (
	"time"

	"gorm.io/gorm"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/oracle"
)

// OracleStore пишет наблюдения и решения судьи
type OracleStore struct {
	gdb *gorm.DB
}

// NewOracleStore оборачивает хендл gorm
func NewOracleStore(gdb *gorm.DB) *OracleStore { return &OracleStore{gdb: gdb} }

// Signal сохраняет одно наблюдение
func (o *OracleStore) Signal(s oracle.Signal) error {
	at := s.Observed
	if at.IsZero() {
		at = time.Now()
	}
	return o.gdb.Create(&AbuseSignal{
		At:        at,
		ProfileID: s.ClientID,
		NodeID:    s.NodeID,
		Class:     s.Kind.String(),
		Count:     int64(s.Count),
	}).Error
}

// Decision сохраняет вердикт вместе со скорером, который его вынес
func (o *OracleStore) Decision(v oracle.Verdict) error {
	at := v.At
	if at.IsZero() {
		at = time.Now()
	}
	return o.gdb.Create(&OracleDecision{
		At:            at,
		SubjectID:     v.ClientID,
		Verdict:       v.Band.String(),
		Confidence:    int32(v.Confidence),
		ScorerVersion: v.Scorer,
	}).Error
}

// Load поднимает сигналы, накопленные с момента since
func (o *OracleStore) Load(since time.Time) ([]oracle.Signal, error) {
	var rows []AbuseSignal
	if err := o.gdb.Where("at >= ?", since).Order("at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]oracle.Signal, 0, len(rows))
	for _, r := range rows {
		kind, ok := fedpb.AbuseKind_value[r.Class]
		if !ok {
			continue
		}
		out = append(out, oracle.Signal{
			ClientID: r.ProfileID,
			NodeID:   r.NodeID,
			Kind:     fedpb.AbuseKind(kind),
			Count:    uint32(r.Count),
			Observed: r.At,
		})
	}
	return out, nil
}

// ForgetSignals снимает наблюдения одного вида за окно.
//
// Нужно для амнистии: расписка, доехавшая из очереди, закрывает период, за
// молчание в котором участника уже наказали
func (o *OracleStore) ForgetSignals(clientID string, kind fedpb.AbuseKind, from, to time.Time) error {
	return o.gdb.
		Where("profile_id = ? AND class = ? AND at >= ? AND at <= ?", clientID, kind.String(), from, to).
		Delete(&AbuseSignal{}).Error
}
