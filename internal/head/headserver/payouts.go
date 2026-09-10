package headserver

import (
	"context"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/oracle"
	"wingsnet.org/federation/internal/head/payout"
	"wingsnet.org/federation/internal/head/stakes"
)

// defaultStatementLimit - сколько эпох показывать донору, если не просили иначе
const defaultStatementLimit = 20

// Payouts - то, что башка знает про деньги. Реализация живёт в базе: эпоха,
// не пережившая рестарт, оставляет донора без выписки и без клейма
type Payouts interface {
	SetPayoutAddress(donorID, address string) error
	PayoutAddress(donorID string) (string, bool, error)
	StatementFor(donorID string, limit int) ([]EpochAccrual, error)
	RecentEpochs(limit int) ([]EpochSummary, error)
	// ProofFor - путь от листа донора к корню эпохи. Без него корень в цепочке
	// есть, а забрать по нему нельзя нихуя
	ProofFor(number uint64, address string) ([][]byte, error)
	// PaidFor - что донору уже выплачено и какой транзакцией
	PaidFor(donorID string) (map[uint64]Payment, error)
}

// Payment - состоявшаяся выплата донору
type Payment struct {
	Micro  int64
	TxRef  string
	PaidAt time.Time
}

// EpochAccrual - начисление донору в одной эпохе
type EpochAccrual struct {
	Number      uint64
	Start       time.Time
	End         time.Time
	AmountMicro uint64
	RootHex     string
	TxRef       string
	// MicroPerGiB - цена гигабайта в этой эпохе. Плавает по казне, поэтому без
	// неё выписка не объясняет, почему в этот раз меньше
	MicroPerGiB int64
	PublishedAt time.Time
}

// EpochSummary - эпоха целиком
type EpochSummary struct {
	Number     uint64
	Start      time.Time
	End        time.Time
	TotalMicro uint64
	Leaves     uint32
	RootHex    string
	TxRef      string
	// MicroPerGiB - цена гигабайта в этой эпохе. Плавает по казне, поэтому без
	// неё выписка не объясняет, почему в этот раз меньше
	MicroPerGiB int64
	PublishedAt time.Time
}

// PendingAccruals - что набежало донору в текущем незакрытом периоде. Отдаётся
// вместе с прайсом, иначе донор видит цифру и ни слова о том, откуда она
type PendingAccruals interface {
	Pending(donorID string, start time.Time) ([]payout.NodeVolume, payout.Micro, error)
	Rate() payout.Rate
	PeriodStart() (time.Time, error)
	Period() time.Duration
}

// SetPendingAccruals включает показ текущего периода
func (s *Server) SetPendingAccruals(p PendingAccruals) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = p
}

// Stakes отвечает, что у донора с залогом
type Stakes interface {
	Ensure(donorID, wallet string)
	Release(ctx context.Context, donorID, wallet string, amount uint64) (stakes.Status, error)
	Status(donorID string) stakes.Status
	Required() uint64
}

// SetStakes включает показ залога. Без цепочки его нет вовсе, и это законный
// режим: федерация месяцами живёт без денег
func (s *Server) SetStakes(st Stakes) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stakes = st
}

// ReleaseStake возвращает залог донору: первый заход заказывает вывод, второй
// после кулдауна отдаёт деньги
func (s *Server) ReleaseStake(ctx context.Context, req *headpb.ReleaseStakeRequest) (*headpb.ReleaseStakeResponse, error) {
	payouts, err := s.payoutsOrErr()
	if err != nil {
		return nil, err
	}
	donor := strings.TrimSpace(req.GetDonorId())
	if donor == "" {
		return nil, status.Error(codes.InvalidArgument, "no donor")
	}
	s.mu.Lock()
	watcher := s.stakes
	s.mu.Unlock()
	if watcher == nil {
		return nil, status.Error(codes.Unimplemented, "this head holds no stakes")
	}
	wallet, _, err := payouts.PayoutAddress(donor)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if wallet == "" {
		return nil, status.Error(codes.FailedPrecondition, "no wallet to send it back to")
	}
	amount := req.GetMicro()
	if amount == 0 {
		amount = watcher.Status(donor).Micro
	}
	if amount == 0 {
		return nil, status.Error(codes.FailedPrecondition, "there is no stake to release")
	}
	state, err := watcher.Release(ctx, donor, wallet, amount)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &headpb.ReleaseStakeResponse{Stake: &headpb.StakeStatus{
		DepositAddress: state.Deposit,
		StakedMicro:    state.Micro,
		RequiredMicro:  watcher.Required(),
		IncomingMicro:  state.IncomingMicro,
		PendingMicro:   state.PendingMicro,
		UnlockUnix:     state.UnlockUnix,
		Enough:         state.Enough(),
	}}, nil
}

// fillStake дописывает в выписку залог
func (s *Server) fillStake(out *headpb.PayoutStatementResponse, donor, wallet string) {
	s.mu.Lock()
	watcher := s.stakes
	s.mu.Unlock()
	if watcher == nil {
		return
	}
	state := watcher.Status(donor)
	// Личный счёт заводится в фоне: экран не должен ждать, пока цепочка
	// соизволит ответить
	watcher.Ensure(donor, wallet)
	out.Stake = &headpb.StakeStatus{
		DepositAddress: state.Deposit,
		StakedMicro:    state.Micro,
		RequiredMicro:  watcher.Required(),
		IncomingMicro:  state.IncomingMicro,
		PendingMicro:   state.PendingMicro,
		UnlockUnix:     state.UnlockUnix,
		Enough:         state.Enough(),
	}
	// Без залога денег не будет, и показывать начисленное как причитающееся
	// нечестно: человек возит трафик даром, пока не внесёт
	if !out.Stake.Enough {
		out.PendingMicro = 0
		out.TotalMicro = 0
		out.ClaimableMicro = 0
	}
}

// SetPayouts включает денежные ручки
func (s *Server) SetPayouts(p Payouts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payouts = p
}

func (s *Server) payoutsOrErr() (Payouts, error) {
	s.mu.Lock()
	p := s.payouts
	s.mu.Unlock()
	if p == nil {
		return nil, status.Error(codes.Unimplemented, "this head accrues no payouts")
	}
	return p, nil
}

// SetPayoutAddress записывает кошелёк донора.
//
// Проверяем тут, а не только в панели: адрес с опечаткой означает деньги,
// ушедшие в никуда, и вернуть их будет неоткуда
func (s *Server) SetPayoutAddress(_ context.Context, req *headpb.SetPayoutAddressRequest) (*headpb.SetPayoutAddressResponse, error) {
	payouts, err := s.payoutsOrErr()
	if err != nil {
		return nil, err
	}
	donor := strings.TrimSpace(req.GetDonorId())
	if donor == "" {
		return nil, status.Error(codes.InvalidArgument, "no donor")
	}
	address := strings.TrimSpace(req.GetAddress())
	if address != "" {
		if err := payout.ValidateSolanaAddress(address); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	if err := payouts.SetPayoutAddress(donor, address); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	// Счёт под токен заводим сами и сразу: донор назвал кошелёк, и на этом его
	// участие заканчивается. Не вышло - выплата подождёт до следующей эпохи, а
	// адрес уже сохранён
	if opener := s.tokenOpener(); opener != nil && address != "" {
		if err := opener(donor, address); err != nil {
			log.Printf("headserver: the token account for %s was not opened: %v", donor, err)
		}
	}
	return &headpb.SetPayoutAddressResponse{}, nil
}

// PayoutStatement отвечает донору на вопрос "сколько мне причитается и за что"
func (s *Server) PayoutStatement(ctx context.Context, req *headpb.PayoutStatementRequest) (*headpb.PayoutStatementResponse, error) {
	payouts, err := s.payoutsOrErr()
	if err != nil {
		return nil, err
	}
	donor := strings.TrimSpace(req.GetDonorId())
	if donor == "" {
		return nil, status.Error(codes.InvalidArgument, "no donor")
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = defaultStatementLimit
	}
	address, _, err := payouts.PayoutAddress(donor)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	rows, err := payouts.StatementFor(donor, limit)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	paid, err := payouts.PaidFor(donor)
	if err != nil {
		log.Printf("headserver: payouts of donor %s are unreadable: %v", donor, err)
	}

	out := &headpb.PayoutStatementResponse{Address: address}
	for _, row := range rows {
		// Пруф считаем только для опубликованных: до цепочки клеймить нечего, а
		// дерево на каждую строку это лишняя работа на ровном месте
		var proof [][]byte
		if row.TxRef != "" && address != "" {
			if got, err := payouts.ProofFor(row.Number, address); err == nil {
				proof = got
			} else {
				log.Printf("headserver: the proof for epoch %d did not build: %v", row.Number, err)
			}
		}
		payment := paid[row.Number]
		out.Epochs = append(out.Epochs, &headpb.EpochAccrual{
			Proof:         proof,
			PayoutTx:      payment.TxRef,
			PaidUnix:      unixOrZero(payment.PaidAt),
			MicroPerGib:   uint64(row.MicroPerGiB),
			Number:        row.Number,
			StartUnix:     row.Start.Unix(),
			EndUnix:       row.End.Unix(),
			AmountMicro:   row.AmountMicro,
			RootHex:       row.RootHex,
			TxRef:         row.TxRef,
			PublishedUnix: unixOrZero(row.PublishedAt),
		})
		out.TotalMicro += row.AmountMicro
		// Клеймить можно только то, чей корень уже в цепочке
		if row.TxRef != "" {
			out.ClaimableMicro += row.AmountMicro
		}
	}
	s.mu.Lock()
	pending := s.pending
	s.mu.Unlock()
	if pending != nil {
		s.fillPending(out, pending, donor)
	}
	s.fillStake(out, donor, address)
	return out, nil
}

// fillPending дописывает в выписку прайс и то, что копится прямо сейчас
func (s *Server) fillPending(out *headpb.PayoutStatementResponse, pending PendingAccruals, donor string) {
	start, err := pending.PeriodStart()
	if err != nil {
		return
	}
	rate := pending.Rate()
	period := pending.Period()
	out.Terms = &headpb.PayoutTerms{
		MicroPerGib:   uint64(rate.MicroPerGiB),
		PeriodSeconds: uint32(period.Seconds()),
	}
	if !start.IsZero() {
		out.Terms.PeriodStartUnix = start.Unix()
		out.Terms.PeriodEndUnix = start.Add(period).Unix()
	}
	volumes, total, err := pending.Pending(donor, start)
	if err != nil {
		return
	}
	out.PendingMicro = uint64(total)
	for _, volume := range volumes {
		out.Pending = append(out.Pending, &headpb.NodeAccrual{
			NodeId:         volume.NodeID,
			Hostname:       s.hostnameOf(volume.NodeID),
			SelfBytes:      volume.SelfBytes,
			ReceiptBytes:   volume.ReceiptBytes,
			BillableBytes:  volume.Billable(),
			ProbeConfirmed: volume.ProbeConfirmed,
			FactorBps:      volume.FactorBps,
			AmountMicro:    uint64(payout.AmountFor(volume, rate)),
		})
	}
}

// hostnameOf - как машина называется у донора. Идентификатор ему ни о чём не
// говорит, а своё железо он знает по имени
func (s *Server) hostnameOf(nodeID string) string {
	node, err := s.reg.Get(nodeID)
	if err != nil || node == nil {
		return ""
	}
	return node.Passport.GetHostname()
}

// Epochs показывает владельцу площадки все закрытые периоды
func (s *Server) Epochs(_ context.Context, req *headpb.EpochsRequest) (*headpb.EpochsResponse, error) {
	payouts, err := s.payoutsOrErr()
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = defaultStatementLimit
	}
	rows, err := payouts.RecentEpochs(limit)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &headpb.EpochsResponse{}
	for _, row := range rows {
		out.Epochs = append(out.Epochs, &headpb.EpochSummary{
			Number:        row.Number,
			StartUnix:     row.Start.Unix(),
			EndUnix:       row.End.Unix(),
			TotalMicro:    row.TotalMicro,
			Leaves:        row.Leaves,
			RootHex:       row.RootHex,
			TxRef:         row.TxRef,
			PublishedUnix: unixOrZero(row.PublishedAt),
		})
	}
	return out, nil
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// InviteTree принимает карту приглашений от панели
type InviteTree interface {
	Replace(ancestors map[string][]string)
	Size() int
}

// SetInviteTree включает приём дерева
func (s *Server) SetInviteTree(tree InviteTree) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inviteTree = tree
}

// ReportInviteTree кладёт свежую карту приглашений.
//
// Карта заменяется целиком: инвайт могли отозвать, а доклеивание к прошлой
// оставило бы связь, которой больше нет
func (s *Server) ReportInviteTree(_ context.Context, req *headpb.ReportInviteTreeRequest) (*headpb.ReportInviteTreeResponse, error) {
	s.mu.Lock()
	tree := s.inviteTree
	s.mu.Unlock()
	if tree == nil {
		return nil, status.Error(codes.Unimplemented, "this head does not judge self-dealing")
	}
	ancestors := make(map[string][]string, len(req.GetSubjects()))
	for _, subject := range req.GetSubjects() {
		id := strings.TrimSpace(subject.GetSubjectId())
		if id == "" {
			continue
		}
		ancestors[id] = subject.GetDonorIds()
	}
	tree.Replace(ancestors)
	return &headpb.ReportInviteTreeResponse{Subjects: uint32(len(ancestors))}, nil
}

// Donations - куда башка складывает подтверждённые заносы. Без хранилища они
// живут до первого выката, а люди платили не за это
type Donations interface {
	Accept(subjectID, reference string, amountMicro uint64, at time.Time) (bool, error)
}

// SetMoneyDonations включает приём заносов деньгами. Имя с уточнением нарочно:
// рядом живут пожертвования ТРАФИКОМ, и путать их нельзя
func (s *Server) SetMoneyDonations(judge *oracle.Judge, store Donations) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.donationJudge, s.donationStore = judge, store
}

// ReportDonation засчитывает занос. Транзакцию проверяет панель: у неё есть и
// аккаунты, и доступ к цепочке, а башка про людей не знает нихуя
func (s *Server) ReportDonation(_ context.Context, req *headpb.ReportDonationRequest) (*headpb.ReportDonationResponse, error) {
	s.mu.Lock()
	judge, store := s.donationJudge, s.donationStore
	s.mu.Unlock()
	if judge == nil {
		return nil, status.Error(codes.Unimplemented, "this head takes no donations")
	}
	subject := strings.TrimSpace(req.GetSubjectId())
	if subject == "" || req.GetAmountMicro() == 0 {
		return nil, status.Error(codes.InvalidArgument, "no subject or amount")
	}
	at := time.Unix(req.GetAtUnix(), 0).UTC()
	if req.GetAtUnix() == 0 {
		at = time.Now().UTC()
	}
	// Повтор по подписи отбивается тут же: одну транзакцию засчитать дважды
	// значит подарить доверие за чужие деньги
	if store != nil {
		fresh, err := store.Accept(subject, strings.TrimSpace(req.GetReference()), req.GetAmountMicro(), at)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		if !fresh {
			return &headpb.ReportDonationResponse{Credit: judge.Credit(subject)}, nil
		}
	}
	judge.Donate(oracle.Credit{SubjectID: subject, AmountMicro: req.GetAmountMicro(), At: at})
	return &headpb.ReportDonationResponse{Credit: judge.Credit(subject)}, nil
}

// RemoveNode выкидывает ноду по просьбе её донора
func (s *Server) RemoveNode(_ context.Context, req *headpb.RemoveNodeRequest) (*headpb.RemoveNodeResponse, error) {
	nodeID := strings.TrimSpace(req.GetNodeId())
	if nodeID == "" {
		return nil, status.Error(codes.InvalidArgument, "no node")
	}
	node, err := s.reg.Get(nodeID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "no such node")
	}
	// Снести чужую машину нельзя даже по случайности: донор в запросе сверяется
	// с тем, за кем нода записана, иначе один донор обнесёт весь флот
	if donor := strings.TrimSpace(req.GetDonorId()); donor != "" && node.DonorID != donor {
		return nil, status.Error(codes.PermissionDenied, "this node belongs to somebody else")
	}
	var moved uint32
	if s.alloc != nil {
		if dropper, ok := s.alloc.(interface{ DropNode(string) int }); ok {
			moved = uint32(dropper.DropNode(nodeID))
		}
	}
	if err := s.reg.Remove(nodeID); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	// Счётчики ноды тоже нахуй: она больше не наша, и держать её трафик в
	// сводке значит показывать владельцу то, чего у него уже нет
	s.agg.Forget(nodeID)
	return &headpb.RemoveNodeResponse{Moved: moved}, nil
}

// SetTokenOpener говорит, чем заводить донору счёт под токен выплат
func (s *Server) SetTokenOpener(open func(donorID, wallet string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenOpen = open
}

func (s *Server) tokenOpener() func(string, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenOpen
}
