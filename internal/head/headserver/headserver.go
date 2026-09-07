// Package headserver is the panel-facing side of the head.
//
// Separate service from fedserver on purpose: this one answers the operator's
// own panel, the other answers third-party servers, and they have no business
// sharing an authentication surface
package headserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fedpb "wingsnet.org/federation/gen/fedpb"
	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/aggregator"
	"wingsnet.org/federation/internal/head/allocator"
	"wingsnet.org/federation/internal/head/donations"
	"wingsnet.org/federation/internal/head/oracle"
	"wingsnet.org/federation/internal/head/registry"
	"wingsnet.org/federation/internal/head/subs"
	"wingsnet.org/federation/internal/head/tokens"
)

// liveInterval is how often a subscriber is pushed a fresh frame. One second
// because the point of the landing page counter is that it visibly moves
const liveInterval = time.Second

// Server implements the FederationHead service
type Server struct {
	headpb.UnimplementedFederationHeadServer

	reg    *registry.Registry
	agg    *aggregator.Aggregator
	tokens *tokens.Store
	// mu защищает только то, что оператор меняет на живой башке
	mu sync.Mutex
	// fleet и pusher появляются, когда башка умеет управлять флотом
	fleet  FleetManager
	pusher ConfigPusher
	// fleetSecret rides along in a minted token: the installer has to key its
	// transport before the node has a secret of its own
	fleetSecret string
	// alloc joins users to nodes. Left nil the user-facing RPCs report that the
	// federation is not serving free users on this head
	alloc Allocations
	// subBase is the public origin a subscription URL is built from
	subBase string
	// installBase is where the installer is served from, and installBudgetGB the
	// donation the pasted command declares
	installBase     string
	installBudgetGB uint32
	// onlineWithin matches the aggregator's staleness window, so a node is not
	// online in one view and offline in the other
	// donations answers "what did I give in June", which the period counter
	// cannot: it resets
	donations DonationHistory
	// vantages и oracle нужны только панели: флоту знать о них незачем
	vantages Vantages
	oracle   *oracle.Judge
	// domains отвечает на вопрос, куда субъект ходил. Отдаётся только владельцу
	// площадки, донору эти данные не показываются вообще
	domains DomainHistory
	// payouts включается только там, где есть база: эпоху надо где-то хранить
	payouts Payouts
	// stakes включается вместе с цепочкой: без неё залога не существует
	stakes Stakes
	// donationJudge и donationStore включают учёт заносов: доверие греет донат,
	// но помнить его надо дольше одного выката
	donationJudge *oracle.Judge
	donationStore Donations
	// upstreams - купленные подписки. Их заводит владелец, и по умолчанию всё
	// это выключено: за чужим сервером Oracle слеп
	upstreams UpstreamPool
	// labels - размеченные снимки. Человек проверяет машинную разметку, прежде
	// чем на ней учить: иначе бустинг выучит её ошибки и станет резать по ним
	labels Labels
	// tokenOpen заводит донору счёт под токен выплат, как только тот назвал
	// кошелёк: дальше от человека ничего не требуется
	tokenOpen func(donorID, wallet string) error
	// pending считает текущий незакрытый период, чтобы донор видел не только
	// закрытые эпохи, но и то, что копится прямо сейчас
	pending PendingAccruals
	// inviteTree - карта приглашений от панели. Дерево у неё, трафик у нас, и
	// без карты нода, возящая трафик своим же людям, неотличима от честной
	inviteTree InviteTree
	// nodeTrust судит НОДЫ, а не людей: шкала другая и последствия другие
	nodeTrust    NodeTrust
	onlineWithin time.Duration
	now          func() time.Time
	liveInterval time.Duration
}

// DonationHistory is the monthly breakdown of a donor's contribution
type DonationHistory interface {
	History(donorID string, months int) ([]donations.Entry, error)
}

// Allocations is what the panel-facing side needs from the allocator. Narrow on
// purpose: nothing here can map a node back to a user
type Allocations interface {
	Ensure(userID string) (*allocator.Allocation, error)
	Revoke(userID string)
	// Entitled - сколько нод полагается по доверию, независимо от того, нашлось
	// ли столько во флоте
	Entitled(userID string) int
	// Usage - сколько пользователь пронёс за текущий период
	Usage(userID string) uint64
	// Speeds - потолки скорости, байт в секунду
	Speeds(userID string) (uplinkBps, downlinkBps uint64)
	// Users - кому вообще выдан доступ. Oracle судит по сигналам, а сигналов на
	// спокойном пользователе нет: без этого списка он в сводке не появится
	Users() []string
	// UsageRows - трафик по строкам списка: сервер плюс транспорт, ровно как их
	// видит человек в приложении
	UsageRows(userID string) []allocator.RowUsage
}

// DomainHistory - откуда брать историю обращений субъекта. Отдаёт страницу и
// общее число: хвост у активного участника уходит в тысячи доменов
type DomainHistory interface {
	TopDomainsPage(subjectID string, since time.Time, limit, offset int) ([]DomainStat, int64, error)
}

// DomainStat - свёрнутая строка истории
type DomainStat struct {
	Domain    string
	Hits      int64
	UpBytes   int64
	DownBytes int64
	LastSeen  time.Time
}

// SetDomainHistory включает показ истории в карточке субъекта
func (s *Server) SetDomainHistory(h DomainHistory) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains = h
}

// SetAllocator wires the user-facing half
func (s *Server) SetAllocator(alloc Allocations, subBase string) {
	s.alloc = alloc
	s.subBase = strings.TrimRight(subBase, "/")
}

// SetInstaller records what a donor should run. The head owns it because it is
// what serves the installer and knows its own public address
func (s *Server) SetInstaller(base string, budgetGB uint32) {
	s.installBase = strings.TrimRight(base, "/")
	s.installBudgetGB = budgetGB
}

// EnsureUser gives a free user a working set of nodes, or returns what they
// already have. Idempotent so the panel can call it on every login
func (s *Server) EnsureUser(_ context.Context, req *headpb.EnsureUserRequest) (*headpb.UserAllocation, error) {
	if s.alloc == nil {
		return nil, status.Error(codes.Unimplemented, "this head does not serve free users")
	}
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "missing user id")
	}
	alloc, err := s.alloc.Ensure(userID)
	if err != nil {
		switch {
		case errors.Is(err, allocator.ErrNoCapacity):
			return nil, status.Error(codes.ResourceExhausted, "no eligible node")
		case errors.Is(err, allocator.ErrQuarantined):
			// Карантин снимает ноды, а не право смотреть на себя. Отказ вместо
			// ответа оставлял человека в чёрном ящике: ни доверия, ни трафика,
			// ни причины, за которую срезали - только красная строка в кабинете
			return &headpb.UserAllocation{
				UserId:      userID,
				Quarantined: true,
				Confidence:  uint32(s.confidenceOf(userID)),
				UsedBytes:   s.alloc.Usage(userID),
				Servers:     usageRows(s.alloc.UsageRows(userID)),
			}, nil
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	uplink, downlink := s.alloc.Speeds(userID)
	return &headpb.UserAllocation{
		UserId:          userID,
		Confidence:      uint32(s.confidenceOf(userID)),
		SubscriptionUrl: s.subBase + subs.Path + alloc.SubToken,
		Nodes:           uint32(len(alloc.Profiles)),
		NodesEntitled:   uint32(s.alloc.Entitled(userID)),
		UsedBytes:       s.alloc.Usage(userID),
		UplinkBps:       uplink,
		DownlinkBps:     downlink,
		StickyUntilUnix: alloc.StickyUntil.Unix(),
		Servers:         usageRows(s.alloc.UsageRows(userID)),
	}, nil
}

// usageRows перекладывает трафик по строкам списка в то, что уедет клиенту
func usageRows(rows []allocator.RowUsage) []*headpb.ServerUsage {
	out := make([]*headpb.ServerUsage, 0, len(rows))
	for _, row := range rows {
		out = append(out, &headpb.ServerUsage{
			Name: row.Name, Transport: row.Transport,
			UpBytes: row.UpBytes, DownBytes: row.DownBytes,
			LastSeenUnix: row.LastSeen,
		})
	}
	return out
}

// RevokeUser takes a user off every node
func (s *Server) RevokeUser(_ context.Context, req *headpb.RevokeUserRequest) (*headpb.RevokeUserResponse, error) {
	if s.alloc == nil {
		return nil, status.Error(codes.Unimplemented, "this head does not serve free users")
	}
	if strings.TrimSpace(req.GetUserId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "missing user id")
	}
	s.alloc.Revoke(req.GetUserId())
	return &headpb.RevokeUserResponse{}, nil
}

// New builds a panel-facing server over the head's existing state
func New(reg *registry.Registry, agg *aggregator.Aggregator, store *tokens.Store, fleetSecret string) *Server {
	return &Server{
		reg:          reg,
		agg:          agg,
		tokens:       store,
		fleetSecret:  fleetSecret,
		onlineWithin: 15 * time.Second,
		now:          time.Now,
		liveInterval: liveInterval,
	}
}

// GetPublicCounters answers the landing page. It carries no identifiers at all,
// because it is served without a session
func (s *Server) GetPublicCounters(_ context.Context, _ *headpb.PublicCountersRequest) (*headpb.PublicCounters, error) {
	snap := s.agg.Global()
	return &headpb.PublicCounters{
		UnixMs:                 snap.At.UnixMilli(),
		NodesOnline:            uint32(snap.NodesOnline),
		UsersOnline:            snap.Sessions,
		DonatedBytesThisPeriod: snap.UpBytes + snap.DownBytes,
		UpRateBps:              snap.UpRateBps,
		DownRateBps:            snap.DownRateBps,
		LifetimeBytes:          snap.LifetimeBytes,
		ProbeBytes:             snap.ProbeBytes,
	}, nil
}

// StreamLive keeps pushing whatever the panel last asked to watch. Bidirectional
// so switching between the fleet view, a donor and a single node costs no new
// dial and no new authentication
func (s *Server) StreamLive(stream headpb.FederationHead_StreamLiveServer) error {
	subs := make(chan *headpb.LiveSubscribe, 1)
	errs := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				errs <- err
				return
			}
			// Only the newest subscription matters, so an unread one is dropped
			// rather than queued
			select {
			case <-subs:
			default:
			}
			subs <- req
		}
	}()

	var current *headpb.LiveSubscribe
	ticker := time.NewTicker(s.liveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-errs:
			return nil
		case req := <-subs:
			current = req
			if err := stream.Send(s.update(current)); err != nil {
				return err
			}
		case <-ticker.C:
			if current == nil {
				continue
			}
			if err := stream.Send(s.update(current)); err != nil {
				return err
			}
		}
	}
}

func (s *Server) update(req *headpb.LiveSubscribe) *headpb.LiveUpdate {
	out := &headpb.LiveUpdate{UnixMs: s.now().UnixMilli()}
	switch req.GetScope() {
	case headpb.LiveScope_LIVE_SCOPE_DONOR:
		out.Donor = s.donorCounters(req.GetDonorId())
	case headpb.LiveScope_LIVE_SCOPE_NODE:
		out.Node = s.nodeCounters(req.GetNodeId())
	default:
		snap := s.agg.Global()
		out.Global = &headpb.GlobalCounters{
			NodesTotal:    uint32(snap.NodesTotal),
			NodesOnline:   uint32(snap.NodesOnline),
			Sessions:      snap.Sessions,
			Streams:       snap.Streams,
			PeriodBytes:   snap.PeriodBytes,
			UpBytes:       snap.UpBytes,
			DownBytes:     snap.DownBytes,
			UpRateBps:     snap.UpRateBps,
			DownRateBps:   snap.DownRateBps,
			LifetimeBytes: snap.LifetimeBytes,
			ProbeBytes:    snap.ProbeBytes,
		}
	}
	return out
}

// defaultBudgetGB - потолок, который уйдёт в команду установки, когда донор не
// назвал свой
func (s *Server) defaultBudgetGB() uint32 {
	if s.installBudgetGB > 0 {
		return s.installBudgetGB
	}
	return defaultDonationGB
}

// DonorSummary is everything a donor may learn about their own contribution
func (s *Server) DonorSummary(_ context.Context, req *headpb.DonorSummaryRequest) (*headpb.DonorCounters, error) {
	if strings.TrimSpace(req.GetDonorId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "missing donor id")
	}
	return s.donorCounters(req.GetDonorId()), nil
}

// SetDonations wires the monthly history. A head without it still serves the
// period counter, and DonorHistory says so instead of returning an empty year
func (s *Server) SetDonations(h DonationHistory) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.donations = h
}

// DonorHistory returns the donor's last months, newest first
func (s *Server) DonorHistory(_ context.Context, req *headpb.DonorHistoryRequest) (*headpb.DonorHistoryResponse, error) {
	donor := strings.TrimSpace(req.GetDonorId())
	if donor == "" {
		return nil, status.Error(codes.InvalidArgument, "missing donor id")
	}
	s.mu.Lock()
	history := s.donations
	s.mu.Unlock()
	if history == nil {
		return nil, status.Error(codes.Unimplemented, "this head keeps no monthly history")
	}
	entries, err := history.History(donor, int(req.GetMonths()))
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	out := &headpb.DonorHistoryResponse{}
	for _, e := range entries {
		out.Months = append(out.Months, &headpb.DonorMonth{Month: e.Month, Bytes: e.Bytes})
	}
	return out, nil
}

// destFor says which borrowed identity a node presents, so the panel can show
// that the fleet is spread across the pool rather than sitting on one target.
func (s *Server) destFor(nodeID string) string {
	// Закреплённый за нодой ответ важнее вычисленного: он уже в выданных
	// ссылках, и панель должна показывать то, чем нода правда прикрывается
	if node, err := s.reg.Get(nodeID); err == nil && node.RealityDest != "" {
		return node.RealityDest
	}
	s.mu.Lock()
	mgr := s.fleet
	s.mu.Unlock()
	if mgr == nil {
		return ""
	}
	return mgr.Settings().DestFor(nodeID)
}

func (s *Server) donorCounters(donorID string) *headpb.DonorCounters {
	live := s.agg.Donor(donorID)
	out := &headpb.DonorCounters{
		DonorId: donorID,
		// Сколько нод у донора, знает реестр, а не счётчики. Агрегатор помнит
		// каждый node_id, который когда-либо репортил, и после перезачисления
		// ноды её прежняя запись остаётся в нём навсегда - счётчик показывал 6
		// при трёх живых нодах.
		NodesOnline: uint32(live.NodesOnline),
		Sessions:    live.Sessions,
		UpBytes:     live.UpBytes,
		DownBytes:   live.DownBytes,
		UpRateBps:   live.UpRateBps,
		DownRateBps: live.DownRateBps,
		// Панель показывает эту цифру в поле бюджета. Молча подставить свой
		// потолок в чужое обязательство это наёбка, а человек должен видеть, под
		// чем подписывается
		DefaultBudgetGb: s.defaultBudgetGB(),
	}
	// The pledged budget and what is spent against it live in the registry, not
	// in the live counters, because they survive a head restart
	for _, n := range s.reg.List() {
		if n.DonorID != donorID {
			continue
		}
		out.Nodes++
		out.DeclaredBudgetBytes += n.DeclaredBudgetBytes
		out.UsedBytes += n.UsedBytes
		out.ProbeBytes += n.ProbeBytes
	}
	return out
}

func (s *Server) nodeCounters(nodeID string) *headpb.NodeCounters {
	node, err := s.reg.Get(nodeID)
	if err != nil {
		return &headpb.NodeCounters{NodeId: nodeID, State: "unknown"}
	}
	return s.counters(node)
}

func (s *Server) counters(node *registry.Node) *headpb.NodeCounters {
	out := &headpb.NodeCounters{
		NodeId:              node.ID,
		State:               stateName(node.State),
		Reason:              node.Reason,
		UsedBytes:           node.UsedBytes,
		ProbeBytes:          node.ProbeBytes,
		DeclaredBudgetBytes: node.DeclaredBudgetBytes,
		Online:              node.Online(s.now(), s.onlineWithin),
	}
	if !node.LastSeen.IsZero() {
		out.LastSeenUnix = node.LastSeen.Unix()
	}
	return out
}

// ListNodes is the operator view, or one donor's slice of it
func (s *Server) ListNodes(_ context.Context, req *headpb.ListNodesRequest) (*headpb.ListNodesResponse, error) {
	now := s.now()
	out := &headpb.ListNodesResponse{}
	for _, n := range s.reg.List() {
		if req.GetDonorId() != "" && n.DonorID != req.GetDonorId() {
			continue
		}
		summary := &headpb.NodeSummary{
			OfferedPorts:        n.OfferedPorts,
			RealityDest:         s.destFor(n.ID),
			NodeId:              n.ID,
			DonorId:             n.DonorID,
			Hostname:            n.Passport.GetHostname(),
			Arch:                n.Passport.GetArch(),
			State:               stateName(n.State),
			Reason:              n.Reason,
			Online:              n.Online(now, s.onlineWithin),
			AesNi:               n.Passport.GetAesNi(),
			XrayVersion:         n.XrayVersion,
			VktpVersion:         n.VktpVersion,
			ProbeBytes:          n.ProbeBytes,
			DeclaredBudgetBytes: n.DeclaredBudgetBytes,
			UsedBytes:           n.UsedBytes,
			Live:                s.counters(n),
		}
		if !n.JoinedAt.IsZero() {
			summary.JoinedUnix = n.JoinedAt.Unix()
		}
		if !n.LastSeen.IsZero() {
			summary.LastSeenUnix = n.LastSeen.Unix()
		}
		out.Nodes = append(out.Nodes, summary)
	}
	return out, nil
}

// defaultDonationGB is what the pasted command declares when nobody said. A
// donor who wants a different number edits the command, which is visible in
// front of them
const defaultDonationGB = 500

// defaultTokenTTL is short: an enroll token is pasted into a terminal within
// minutes of being minted, and a long-lived one is just a credential lying around
const defaultTokenTTL = 30 * time.Minute

// maxTokenUses bounds a fleet token. Big enough for a cluster, small enough that
// a leaked one is a contained problem rather than an open door
const maxTokenUses = 64

// MintEnrollToken hands the panel the value the installer takes verbatim
func (s *Server) MintEnrollToken(_ context.Context, req *headpb.MintEnrollTokenRequest) (*headpb.MintEnrollTokenResponse, error) {
	donorID := strings.TrimSpace(req.GetDonorId())
	if donorID == "" {
		return nil, status.Error(codes.InvalidArgument, "missing donor id")
	}
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	// Capped rather than trusted: the panel asks, but a token good for a
	// thousand joins is a credential worth stealing, and nobody donates a
	// thousand hosts in one ttl
	uses := req.GetUses()
	if uses == 0 {
		uses = 1
	}
	if uses > maxTokenUses {
		return nil, status.Errorf(codes.InvalidArgument,
			"a token may authorise at most %d joins", maxTokenUses)
	}
	token, err := s.tokens.MintFor(donorID, ttl, uses)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	compound := tokens.JoinCompound(s.fleetSecret, token)
	resp := &headpb.MintEnrollTokenResponse{
		EnrollToken: compound,
		ExpiresUnix: s.now().Add(ttl).Unix(),
		Uses:        uses,
	}
	if s.installBase != "" {
		// Донор называет потолок при выписке токена: править его после того, как
		// сервер уже зашёл, значит сперва отдать больше, чем собирался
		budget := req.GetBudgetGb()
		if budget == 0 {
			budget = s.installBudgetGB
		}
		if budget == 0 {
			budget = defaultDonationGB
		}
		resp.InstallCommand = fmt.Sprintf("curl -fsSL %s%s | sh -s -- %s %d",
			s.installBase, subs.InstallerPath, compound, budget)
	}
	return resp, nil
}

// SetNodeState is the manual override behind the automatic rotation
func (s *Server) SetNodeState(_ context.Context, req *headpb.SetNodeStateRequest) (*headpb.SetNodeStateResponse, error) {
	state, ok := parseState(req.GetState())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unknown rotation state")
	}
	if err := s.reg.SetState(req.GetNodeId(), state, req.GetReason()); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &headpb.SetNodeStateResponse{}, nil
}

func stateName(state fedpb.RotationState) string {
	switch state {
	case fedpb.RotationState_ROTATION_STATE_ACTIVE:
		return "active"
	case fedpb.RotationState_ROTATION_STATE_DRAINING:
		return "draining"
	case fedpb.RotationState_ROTATION_STATE_PARKED:
		return "parked"
	case fedpb.RotationState_ROTATION_STATE_QUARANTINED:
		return "quarantined"
	default:
		return "unspecified"
	}
}

func parseState(name string) (fedpb.RotationState, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "active":
		return fedpb.RotationState_ROTATION_STATE_ACTIVE, true
	case "draining":
		return fedpb.RotationState_ROTATION_STATE_DRAINING, true
	case "parked":
		return fedpb.RotationState_ROTATION_STATE_PARKED, true
	case "quarantined":
		return fedpb.RotationState_ROTATION_STATE_QUARANTINED, true
	default:
		return fedpb.RotationState_ROTATION_STATE_UNSPECIFIED, false
	}
}

// confidenceOf - оценка Oracle по человеку. Без источника считаем, что он чист:
// молчащий Oracle не повод рисовать в кабинете ноль
func (s *Server) confidenceOf(userID string) int {
	s.mu.Lock()
	judge := s.donationJudge
	s.mu.Unlock()
	if judge == nil {
		return oracle.StartingConfidence
	}
	return judge.Judge(userID).Confidence
}
