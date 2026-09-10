package headserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	headpb "wingsnet.org/federation/gen/headpb"
)

// Разметку показывают человеку не ради любопытства: на ней учится бустинг,
// который потом режет людям доступ. Машина на пограничных случаях плавает, и
// непроверенная метка означает, что модель выучит её ошибку и станет повторять
// уверенно.
//
// Поэтому вердикт человека тут старше машинного всегда и затиранию не подлежит

// Labels - что панели нужно от хранилища снимков
type Labels interface {
	// Page отдаёт страницу разметки. accusedOnly оставляет только обвинения:
	// чистых на порядок больше, а смотреть надо туда, где кого-то записали в
	// мошенники
	Page(limit, offset int, accusedOnly bool) (rows []LabelRow, total int, err error)
	// Counts - сколько размечено машиной и сколько подтверждено человеком
	Counts() (byMachine, byHuman int, err error)
	// Judge ставит приговор человека
	Judge(id uint64, label int16) error
}

// LabelRow - один размеченный снимок
type LabelRow struct {
	ID        uint64
	AtUnix    int64
	SubjectID string
	Label     int16
	LabelBy   string
	Why       string
	Values    map[string]float64
}

// LabelByHuman - подпись человеческой разметки
const LabelByHuman = "human"

// SetLabels включает раздел разметки
func (s *Server) SetLabels(store Labels) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.labels = store
}

func (s *Server) labelsOrErr() (Labels, error) {
	s.mu.Lock()
	store := s.labels
	s.mu.Unlock()
	if store == nil {
		return nil, status.Error(codes.Unimplemented, "this head keeps no labelled snapshots")
	}
	return store, nil
}

// OracleLabels отдаёт страницу разметки
func (s *Server) OracleLabels(_ context.Context, req *headpb.OracleLabelsRequest) (*headpb.OracleLabelsResponse, error) {
	store, err := s.labelsOrErr()
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return labelsView(store, limit, int(req.GetOffset()), req.GetAccusedOnly())
}

// SetOracleLabel записывает приговор человека
func (s *Server) SetOracleLabel(_ context.Context, req *headpb.SetOracleLabelRequest) (*headpb.OracleLabelsResponse, error) {
	store, err := s.labelsOrErr()
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "a label needs a snapshot id")
	}
	label := int16(req.GetLabel())
	if label < -1 || label > 1 {
		return nil, status.Error(codes.InvalidArgument, "a label is -1, 0 or 1")
	}
	if err := store.Judge(req.GetId(), label); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return labelsView(store, 50, 0, false)
}

func labelsView(store Labels, limit, offset int, accusedOnly bool) (*headpb.OracleLabelsResponse, error) {
	rows, total, err := store.Page(limit, offset, accusedOnly)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &headpb.OracleLabelsResponse{Total: uint32(total)}
	if machine, human, err := store.Counts(); err == nil {
		out.ByMachine, out.ByHuman = uint32(machine), uint32(human)
	}
	for _, row := range rows {
		out.Labels = append(out.Labels, &headpb.OracleLabel{
			Id: row.ID, AtUnix: row.AtUnix, SubjectId: row.SubjectID,
			Label: int32(row.Label), LabelBy: row.LabelBy, Why: row.Why,
			Values: row.Values,
		})
	}
	return out, nil
}
