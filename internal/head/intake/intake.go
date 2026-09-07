// Package intake принимает от клиента то, что клиент подписывает сам.
//
// Расписка это единственная цифра о трафике, которой можно верить: свои
// счётчики нода рисует сама, и платить по ним значит платить за воздух. Ключ
// живёт только на устройстве, поэтому подделать расписку нода не может
package intake

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fedpb "wingsnet.org/federation/gen/fedpb"
	intakepb "wingsnet.org/federation/gen/intakepb"
	"wingsnet.org/federation/pkg/receipt"
)

// maxSkew - насколько окно расписки может смотреть в будущее. Часы на телефоне
// врут, но не на сутки, а расписка из будущего это заявка на трафик, которого
// ещё не было
const maxSkew = 10 * time.Minute

// maxAge - насколько старую расписку ещё принимаем. Телефон бывает офлайн, но
// неделя это уже попытка досыпать задним числом
const maxAge = 7 * 24 * time.Hour

// Keys хранит публичные половины
type Keys interface {
	Put(subjectID string, key []byte) (changed bool, err error)
	Get(subjectID string) ([]byte, bool, error)
}

// Sink принимает то, что прошло проверку
type Sink interface {
	// Accept сохраняет расписку. Повтор по nonce должен отбиваться тут же
	Accept(subjectID string, r *fedpb.TrafficReceipt) error
}

// Server - реализация приёма
type Server struct {
	intakepb.UnimplementedIntakeServer
	keys Keys
	sink Sink
	now  func() time.Time
	// seen и addressSink нужны для сверки заявленного клиентом адреса с тем,
	// что видит нода. Без них приём работает как обычно
	seen        Seen
	addressSink func(subjectID, claimed string)
	// held отвечает, была ли эта нода у человека в это окно, и nodeOf переводит
	// адрес из расписки в идентификатор ноды. Клиент подписывает то, что видит в
	// ссылке, внутренних id он не знает
	held   func(userID, nodeID string, windowEnd time.Time) bool
	nodeOf func(address string) (string, bool)
	// forgive снимает обвинение в молчании за окно, которое расписка закрыла
	// задним числом
	forgive func(subjectID string, from, to time.Time) int
}

// SetAmnesty включает прощение за окна, закрытые досланными расписками.
//
// Очередь на телефоне переживает и потерю сети, и наши собственные обломы
// доставки, поэтому расписка приезжает и через сутки. Наказание за молчание к
// этому моменту уже выставлено, и снять его должен тот же факт, который его
// опроверг
func (s *Server) SetAmnesty(forgive func(subjectID string, from, to time.Time) int) {
	s.forgive = forgive
}

// SetGrants включает проверку расписки по журналу выдачи башки.
//
// Это единственный честный источник для такой проверки. Сверять с самоотчётом
// ноды нельзя: агент у донора свой, и нода, перестав рапортовать трафик, отбила
// бы клиентам подписи и вышла из-под учёта
func (s *Server) SetGrants(
	held func(userID, nodeID string, windowEnd time.Time) bool,
	nodeOf func(address string) (string, bool),
) {
	s.held, s.nodeOf = held, nodeOf
}

func New(keys Keys, sink Sink) *Server {
	return &Server{keys: keys, sink: sink, now: time.Now}
}

// RegisterKey запоминает ключ устройства
func (s *Server) RegisterKey(_ context.Context, req *intakepb.RegisterKeyRequest) (*intakepb.RegisterKeyResponse, error) {
	subject := req.GetSubjectId()
	key := req.GetPublicKey()
	if subject == "" || len(key) != ed25519.PublicKeySize {
		return nil, status.Error(codes.InvalidArgument, "bad subject or key")
	}
	changed, err := s.keys.Put(subject, key)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &intakepb.RegisterKeyResponse{Changed: changed}, nil
}

// SubmitReceipts проверяет подписи и складывает то, что сошлось
func (s *Server) SubmitReceipts(_ context.Context, req *intakepb.SubmitReceiptsRequest) (*intakepb.SubmitReceiptsResponse, error) {
	subject := req.GetSubjectId()
	if subject == "" {
		return nil, status.Error(codes.InvalidArgument, "no subject")
	}
	key, ok, err := s.keys.Get(subject)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "no registered key")
	}

	s.checkAddress(subject, req.GetClientIp())

	out := &intakepb.SubmitReceiptsResponse{}
	now := s.now()
	for _, r := range req.GetReceipts() {
		if err := s.check(subject, key, r, now); err != nil {
			out.Rejected++
			if out.Reason == "" {
				out.Reason = err.Error()
			}
			// Отказ уходит только в ответ, а клиент чистит очередь и на нём:
			// без этой строки потеря не оставляет следа нигде
			log.Printf("intake: %s receipt for %s rejected: %v", subject, r.GetNodeId(), err)
			continue
		}
		if err := s.sink.Accept(subject, r); err != nil {
			out.Rejected++
			if out.Reason == "" {
				out.Reason = err.Error()
			}
			log.Printf("intake: %s receipt for %s not stored: %v", subject, r.GetNodeId(), err)
			continue
		}
		out.Accepted++
		s.amnesty(subject, r, now)
	}
	if out.Accepted > 0 {
		log.Printf("intake: %s brought %d receipts, %d rejected", subject, out.Accepted, out.Rejected)
	}
	return out, nil
}

var (
	errWrongSubject = errors.New("receipt names somebody else")
	errFuture       = errors.New("receipt window is in the future")
	errStale        = errors.New("receipt window is too old")
	errBackwards    = errors.New("receipt window ends before it starts")
	errNotGranted   = errors.New("receipt names a node this subject never held")
	errTooFast      = errors.New("receipt claims more than the window could carry")
)

// maxWindowBps - потолок на окно расписки. Десять гигабит на телефоне не бывает,
// а без потолка одна подпись заявляет терабайты и перекашивает всё, что по ним
// считается
const maxWindowBps = 10 << 30

// check - всё, что должно сойтись, прежде чем расписке верить
// amnesty снимает обвинение в молчании, если расписка закрыла прошлое окно.
//
// Свежая расписка ничего не прощает: наказания за окно, которое ещё идёт, никто
// и не выставлял
func (s *Server) amnesty(subject string, r *fedpb.TrafficReceipt, now time.Time) {
	if s.forgive == nil {
		return
	}
	start := time.Unix(r.GetWindowStartUnix(), 0)
	end := time.Unix(r.GetWindowEndUnix(), 0)
	// Прощаем только закрытое прошлое: за идущее окно никого ещё не обвиняли
	if !end.Before(now) {
		return
	}
	if forgiven := s.forgive(subject, start, end); forgiven > 0 {
		log.Printf("intake: %s closed %s..%s late, %d accusations dropped",
			subject, start.Format(time.RFC3339), end.Format(time.RFC3339), forgiven)
	}
}

func (s *Server) check(subject string, key []byte, r *fedpb.TrafficReceipt, now time.Time) error {
	// Клиент подписывает своё имя, поэтому чужое имя в расписке не пройдёт
	// проверку подписи. Но сверить дешевле, чем считать криптографию
	if r.GetClientId() != subject {
		return errWrongSubject
	}
	start := time.Unix(r.GetWindowStartUnix(), 0)
	end := time.Unix(r.GetWindowEndUnix(), 0)
	if !end.After(start) {
		return errBackwards
	}
	if end.After(now.Add(maxSkew)) {
		return errFuture
	}
	if end.Before(now.Add(-maxAge)) {
		return errStale
	}
	seconds := uint64(end.Sub(start).Seconds())
	if seconds == 0 {
		seconds = 1
	}
	if (r.GetPayloadUpBytes()+r.GetPayloadDownBytes())/seconds > maxWindowBps/8 {
		return errTooFast
	}
	if s.held != nil && s.nodeOf != nil {
		nodeID, known := s.nodeOf(r.GetNodeId())
		if !known || !s.held(subject, nodeID, end) {
			return errNotGranted
		}
	}
	return receipt.Verify(ed25519.PublicKey(key), r)
}
