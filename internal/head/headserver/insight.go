package headserver

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fedpb "wingsnet.org/federation/gen/fedpb"
	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/fedserver"
	"wingsnet.org/federation/internal/head/oracle"
)

// probeOnlineWithin - за сколько молчания точка наблюдения считается погасшей
const probeOnlineWithin = 2 * time.Minute

// defaultOracleLimit - сколько подозреваемых отдавать без явного запроса
const defaultOracleLimit = 20

// Vantages - то, что знает о зондах половина, смотрящая во флот
type Vantages interface {
	Probes() []fedserver.ProbeInfo
	WakeProbes() uint32
}

// SetVantages подключает список зондов
func (s *Server) SetVantages(v Vantages) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vantages = v
}

// SetOracle подключает судью
func (s *Server) SetOracle(j *oracle.Judge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oracle = j
}

// ProbeReports отдаёт все замеры, которые держит башка, свежие первыми
func (s *Server) ProbeReports(_ context.Context, req *headpb.ProbeReportsRequest) (*headpb.ProbeReportsResponse, error) {
	s.mu.Lock()
	vantages := s.vantages
	s.mu.Unlock()

	out := &headpb.ProbeReportsResponse{}
	counts := map[string]uint32{}
	for _, n := range s.reg.List() {
		for _, r := range n.Reachability {
			counts[r.ProbeID]++
			out.Measurements = append(out.Measurements, &headpb.ProbeMeasurement{
				NodeId:      n.ID,
				Hostname:    n.Passport.GetHostname(),
				Address:     r.Address,
				Transport:   r.Transport,
				Ok:          r.OK,
				HandshakeMs: r.HandshakeMs,
				RttMs:       r.RTTMs,
				DownloadBps: r.DownloadBps,
				Error:       r.Error,
				ProbeId:     r.ProbeID,
				AtUnix:      r.At.Unix(),
			})
		}
	}
	sort.Slice(out.Measurements, func(i, j int) bool {
		return out.Measurements[i].GetAtUnix() > out.Measurements[j].GetAtUnix()
	})
	out.Total = uint32(len(out.Measurements))
	out.Measurements = pageOf(out.Measurements, req.GetOffset(), req.GetLimit())

	if vantages != nil {
		now := s.now()
		for _, p := range vantages.Probes() {
			out.Vantages = append(out.Vantages, &headpb.ProbeVantage{
				ProbeId:      p.ID,
				Region:       p.Region,
				Isp:          p.ISP,
				Asn:          p.ASN,
				Version:      p.Version,
				Online:       now.Sub(p.LastSeen) <= probeOnlineWithin,
				LastSeenUnix: p.LastSeen.Unix(),
				Measurements: counts[p.ID],
			})
		}
	}
	return out, nil
}

// RunProbes просит точки наблюдения замерить прямо сейчас
func (s *Server) RunProbes(_ context.Context, _ *headpb.RunProbesRequest) (*headpb.RunProbesResponse, error) {
	s.mu.Lock()
	vantages := s.vantages
	s.mu.Unlock()
	if vantages == nil {
		return nil, status.Error(codes.Unimplemented, "this head has no probes")
	}
	return &headpb.RunProbesResponse{Probes: vantages.WakeProbes()}, nil
}

// mergeSubjects складывает обвиняемых и тех, кому выдан доступ, без повторов
func mergeSubjects(accused, users []string) []string {
	seen := make(map[string]struct{}, len(accused)+len(users))
	out := make([]string, 0, len(accused)+len(users))
	for _, list := range [][]string{accused, users} {
		for _, id := range list {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// OracleOverview показывает, чем занят судья. Ни одного поля, по которому
// профиль сводится к человеку: у башки этих данных нет
func (s *Server) OracleOverview(_ context.Context, req *headpb.OracleOverviewRequest) (*headpb.OracleOverviewResponse, error) {
	s.mu.Lock()
	judge := s.oracle
	s.mu.Unlock()
	if judge == nil {
		return nil, status.Error(codes.Unimplemented, "this head runs no oracle")
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = defaultOracleLimit
	}

	out := &headpb.OracleOverviewResponse{}
	signals := map[string]*headpb.OracleClass{}
	signalSubjects := map[string]map[string]struct{}{}
	day := s.now().Add(-24 * time.Hour)

	accused := judge.Accused()
	out.Watched = uint32(len(accused))

	// Полосы считаются по всем, кому выдан доступ: у спокойного пользователя
	// сигналов нет, и в списке обвиняемых он не появится - а доступ у него есть
	watch := accused
	if s.alloc != nil {
		watch = mergeSubjects(accused, s.alloc.Users())
	}
	if asked := req.GetSubjectIds(); len(asked) > 0 {
		watch = asked
		out.Watched = uint32(len(asked))
	}
	out.SubjectsTotal = uint32(len(watch))
	for _, id := range watch {
		verdict := judge.Judge(id)
		switch verdict.Band {
		case oracle.BandFull:
			out.Full++
		case oracle.BandReduced:
			out.Reduced++
		default:
			out.Quarantined++
		}
		subject := &headpb.OracleSubject{
			SubjectId:  id,
			Confidence: int32(verdict.Confidence),
			Band:       verdict.Band.String(),
			Scorer:     verdict.Scorer,
			AtUnix:     verdict.At.Unix(),
			Classes:    classesOf(verdict.Contributions),
		}
		if shadow, ok := judge.Shadow(id); ok {
			subject.ShadowBand = shadow.Band.String()
			subject.ShadowConfidence = int32(shadow.Confidence)
			out.ShadowScorer = shadow.Scorer
		}
		out.Scorer = verdict.Scorer
		out.Subjects = append(out.Subjects, subject)

		for _, sig := range judge.Features(id) {
			if sig.Observed.Before(day) {
				continue
			}
			kind := kindName(sig.Kind)
			if signals[kind] == nil {
				signals[kind] = &headpb.OracleClass{Kind: kind}
			}
			signals[kind].Count += sig.Count
			// Субъекты считаются отдельно от сигналов: сто срабатываний у одного
			// человека и по одному у сотни - это разные истории
			if _, counted := signalSubjects[kind][id]; !counted {
				if signalSubjects[kind] == nil {
					signalSubjects[kind] = map[string]struct{}{}
				}
				signalSubjects[kind][id] = struct{}{}
				signals[kind].Subjects++
			}
		}
	}

	// Худшие первыми: экран открывают, чтобы увидеть проблемных
	sort.Slice(out.Subjects, func(i, j int) bool {
		return out.Subjects[i].GetConfidence() < out.Subjects[j].GetConfidence()
	})
	out.Total = uint32(len(out.Subjects))
	out.Offset = req.GetOffset()
	out.Subjects = pageOf(out.Subjects, req.GetOffset(), uint32(limit))
	// Доля класса среди всех сигналов: голое число срабатываний не говорит,
	// на что вообще уходит внимание Oracle
	var totalSignals uint32
	for _, c := range signals {
		totalSignals += c.GetCount()
	}
	for _, c := range signals {
		if totalSignals > 0 {
			c.SharePct = float64(c.GetCount()) * 100 / float64(totalSignals)
		}
		out.Signals = append(out.Signals, c)
	}
	sort.Slice(out.Signals, func(i, j int) bool { return out.Signals[i].GetCount() > out.Signals[j].GetCount() })
	return out, nil
}

func classesOf(contributions map[fedpb.AbuseKind]float64) []*headpb.OracleClass {
	out := make([]*headpb.OracleClass, 0, len(contributions))
	for kind, cost := range contributions {
		out = append(out, &headpb.OracleClass{Kind: kindName(kind), Weight: cost})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetWeight() > out[j].GetWeight() })
	return out
}

// kindName сокращает имя из прото до того, что можно показать: ABUSE_KIND_
// перед каждым значением на экране только шумит
func kindName(kind fedpb.AbuseKind) string {
	return strings.ToLower(strings.TrimPrefix(kind.String(), "ABUSE_KIND_"))
}

// OracleSubject отвечает на вопрос "за что" по одному субъекту: вердикт вместе
// с сырыми сигналами, которые к нему привели
func (s *Server) OracleSubject(_ context.Context, req *headpb.OracleSubjectRequest) (*headpb.OracleSubjectResponse, error) {
	id := strings.TrimSpace(req.GetSubjectId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "missing subject id")
	}
	s.mu.Lock()
	judge := s.oracle
	s.mu.Unlock()
	if judge == nil {
		return nil, status.Error(codes.Unimplemented, "this head runs no oracle")
	}

	verdict := judge.Judge(id)
	out := &headpb.OracleSubjectResponse{
		Subject: &headpb.OracleSubject{
			SubjectId:  id,
			Confidence: int32(verdict.Confidence),
			Band:       verdict.Band.String(),
			Scorer:     verdict.Scorer,
			AtUnix:     verdict.At.Unix(),
			Classes:    classesOf(verdict.Contributions),
		},
	}
	if shadow, ok := judge.Shadow(id); ok {
		out.Subject.ShadowBand = shadow.Band.String()
		out.Subject.ShadowConfidence = int32(shadow.Confidence)
	}
	signals := judge.Features(id)
	// Свежие сверху, иначе на второй странице оказывается вчерашнее, а на первой
	// то, что судья успел записать раньше всех
	sort.Slice(signals, func(i, j int) bool { return signals[i].Observed.After(signals[j].Observed) })
	out.SignalsTotal = uint32(len(signals))
	for _, sig := range pageOf(signals, req.GetSignalOffset(), signalPage(req.GetSignalLimit())) {
		out.Signals = append(out.Signals, &headpb.OracleSignal{
			Kind:   kindName(sig.Kind),
			Count:  sig.Count,
			AtUnix: sig.Observed.Unix(),
			NodeId: sig.NodeID,
		})
	}
	s.mu.Lock()
	history := s.domains
	s.mu.Unlock()
	if history != nil {
		window := domainWindow
		if hours := req.GetWindowHours(); hours > 0 {
			window = time.Duration(hours) * time.Hour
		}
		rows, total, err := history.TopDomainsPage(
			id, time.Now().Add(-window),
			int(domainPage(req.GetDomainLimit())), int(req.GetDomainOffset()),
		)
		if err != nil {
			log.Printf("headserver: domain history unreadable: %v", err)
		}
		out.DomainsTotal = uint32(total)
		for _, row := range rows {
			out.Domains = append(out.Domains, &headpb.OracleDomain{
				Domain:       row.Domain,
				Hits:         row.Hits,
				UpBytes:      uint64(row.UpBytes),
				DownBytes:    uint64(row.DownBytes),
				LastSeenUnix: row.LastSeen.Unix(),
			})
		}
	}
	return out, nil
}

// Сколько истории поднимать за раз. Неделя и три десятка строк на страницу,
// дальше начинается длинный хвост, в котором глазами всё равно нихуя не разобрать
const (
	domainWindow  = 7 * 24 * time.Hour
	domainTop     = 30
	signalTop     = 50
	oraclePageMax = 500
)

// domainPage и signalPage держат страницу в берегах, чтобы запросом с limit в
// миллион никто не выдоил базу целиком
func domainPage(limit uint32) uint32 { return clampPage(limit, domainTop) }

func signalPage(limit uint32) uint32 { return clampPage(limit, signalTop) }

func clampPage(limit, fallback uint32) uint32 {
	switch {
	case limit == 0:
		return fallback
	case limit > oraclePageMax:
		return oraclePageMax
	default:
		return limit
	}
}

// pageOf нарезает страницу, не падая на смещении за концом списка
func pageOf[T any](items []T, offset, limit uint32) []T {
	if limit == 0 {
		return items
	}
	if int(offset) >= len(items) {
		return nil
	}
	end := int(offset) + int(limit)
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}
