// Package fedserver serves the agent-facing and probe-facing side of the
// federation: enrollment plus the long-lived streams that carry everything else
package fedserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"google.golang.org/protobuf/proto"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/aggregator"
	"wingsnet.org/federation/internal/head/fleet"
	"wingsnet.org/federation/internal/head/registry"
	"wingsnet.org/federation/internal/scan"
)

// EnrollTokens hands out and burns the single-use tokens an installer presents
type EnrollTokens interface {
	// Redeem consumes a token, returning the donor it belongs to. A token that
	// was already used, expired or never existed must fail
	Redeem(token string) (donorID string, err error)
}

// Server implements the Federation gRPC service
// Usage - куда складывать трафик выданных профилей
type Usage interface {
	AddUsage(profileID, transport string, up, down uint64)
}

type Server struct {
	fedpb.UnimplementedFederationServer

	reg    *registry.Registry
	tokens EnrollTokens
	agg    *aggregator.Aggregator
	// usage принимает трафик по выданным профилям. Пустой, когда башка не
	// раздаёт бесплатных юзеров
	usage Usage
	// peerOwners - чей пир релея, чтобы трафик VK TURN лёг человеку
	peerOwners PeerOwners

	// headEndpoint is what a freshly enrolled node should dial from now on. The
	// installer only knows the address it was handed on the command line, which
	// may be a bootstrap hostname rather than the one the fleet should use
	headEndpoint      string
	heartbeatInterval time.Duration
	statsInterval     time.Duration
	realityCandidates []string

	mu     sync.Mutex
	probes map[string]ProbeInfo
	// probeWake - каналы ручного запуска, по одному на открытую сессию
	probeWake []chan struct{}
	// sessions is every open agent stream, so the head can push a command to one
	// node without waiting for it to say something first
	sessions map[string]*session
	// pending - кто ждёт ответа на просьбу сходить наружу вместо башки
	pending *pending
	// nodeConfig is what every node is told to serve. Per-node configs land with
	// the assignment work; one shared config is enough to get a node running
	nodeConfig *fedpb.NodeConfig
	// fleet carries the operator's build choices onto every config handed out
	fleet Fleet
	// profilesFor answers what a node should be serving. Set by the allocator;
	// left nil the head simply never reconciles
	profilesFor func(nodeID string) []*fedpb.ProfileSpec
	// probeTargets and probeIngest are the vantage-point half. Left nil the head
	// accepts probe sessions and gives them nothing to do
	probeTargets func() *fedpb.ProbeTask
	probeIngest  func(probeID string, report *fedpb.ProbeReport)
	// abuseIngest files what a node reported against the user behind the profile.
	// Left nil, accusations are logged and dropped rather than acted on
	abuseIngest func(signal *fedpb.AbuseSignal, nodeID string)
	// domainIngest складывает наблюдения о том, куда ходили профили федерации
	domainIngest  func(batch *fedpb.DomainBatch, nodeID string)
	relayMode     func(nodeID string, federation bool)
	receiptIngest func(receipts []*fedpb.TrafficReceipt)
}

// SetAbuseSink wires where abuse signals go
func (s *Server) SetAbuseSink(fn func(*fedpb.AbuseSignal, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abuseIngest = fn
}

func (s *Server) abuseSink() func(*fedpb.AbuseSignal, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.abuseIngest
}

// SetReceiptSink wires where receipts carried by a node land
func (s *Server) SetReceiptSink(fn func([]*fedpb.TrafficReceipt)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receiptIngest = fn
}

func (s *Server) receiptSink() func([]*fedpb.TrafficReceipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receiptIngest
}

// SetRelayModeSink wires who hears that a relay is not locked to its own
// WireGuard
func (s *Server) SetRelayModeSink(fn func(nodeID string, federation bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relayMode = fn
}

func (s *Server) relayModeSink() func(string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.relayMode
}

// SetDomainSink wires where domain observations land
func (s *Server) SetDomainSink(fn func(*fedpb.DomainBatch, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domainIngest = fn
}

func (s *Server) domainSink() func(*fedpb.DomainBatch, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.domainIngest
}

// SetProbeFleet wires what vantage points measure and where their reports land
func (s *Server) SetProbeFleet(targets func() *fedpb.ProbeTask, ingest func(string, *fedpb.ProbeReport)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeTargets, s.probeIngest = targets, ingest
}

func (s *Server) probeFleet() (func() *fedpb.ProbeTask, func(string, *fedpb.ProbeReport)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.probeTargets, s.probeIngest
}

// SetProfileSource wires what a node should be serving, so a reconnecting node
// can be brought back in step
// SetUsage wires where per-profile traffic goes
func (s *Server) SetUsage(u Usage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usage = u
}

func (s *Server) SetProfileSource(fn func(nodeID string) []*fedpb.ProfileSpec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profilesFor = fn
}

func (s *Server) currentProfiles(nodeID string) ([]*fedpb.ProfileSpec, bool) {
	s.mu.Lock()
	fn := s.profilesFor
	s.mu.Unlock()
	if fn == nil {
		return nil, false
	}
	return fn(nodeID), true
}

// SetFleet attaches the operator's fleet-wide settings. Nil is fine: a head
// started without a database still serves whatever config it was given.
func (s *Server) SetFleet(f Fleet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fleet = f
}

// Fleet is the part of the settings manager this server needs
type Fleet interface {
	Settings() fleet.Settings
}

// SetNodeConfig sets what nodes are pushed on connect, and hands it to the ones
// already connected.
//
// Without the second half a change only reached a node when it happened to
// reconnect: sessions are long-lived, so an operator saving a setting saw
// nothing happen for hours and concluded the panel was broken.
func (s *Server) SetNodeConfig(cfg *fedpb.NodeConfig) {
	s.mu.Lock()
	s.nodeConfig = cfg
	s.mu.Unlock()

	for _, nodeID := range s.Connected() {
		// Каждой ноде своё: порты и заимствованная личность у них разные
		own := s.ConfigFor(nodeID)
		if own == nil {
			continue
		}
		if err := s.Push(nodeID, &fedpb.HeadFrame{
			Frame: &fedpb.HeadFrame_ConfigPush{ConfigPush: own},
		}); err != nil {
			// Не беда: нода подберёт конфиг на ближайшем переподключении
			log.Printf("fedserver: could not push the new config to %s: %v", nodeID, err)
		}
	}
}

// CurrentConfig is what the fleet is being told to serve. Exported so profiles
// are rendered against the same config the nodes applied
func (s *Server) CurrentConfig() *fedpb.NodeConfig { return s.currentConfig() }

// ConfigFor is CurrentConfig with the node's own ports applied.
//
// 443 is what makes a REALITY inbound look like an ordinary web server, so it
// is the default and every node gets it when it can. But a donated host often
// already serves something there, and refusing such a host would turn away most
// of the machines people actually have. So a node reports at enrolment which
// ports it could take, and the head renders that node's inbounds - and, through
// Links, that node's vless URLs - against those instead.
//
// The order is positional and matches the inbounds: the first offered port is
// the tcp inbound, the second the xhttp one. Offering fewer leaves the rest on
// the fleet default.
func (s *Server) ConfigFor(nodeID string) *fedpb.NodeConfig {
	cfg := s.currentConfig()
	if cfg == nil {
		return nil
	}
	out := proto.CloneOf(cfg)
	s.mu.Lock()
	f := s.fleet
	s.mu.Unlock()
	if f != nil {
		set := f.Settings()
		out = set.Apply(out)
		// Разный dest на разные ноды: общий на весь флот означает, что одно
		// правило у цензора роняет всех разом.
		//
		// Закреплённый за нодой имеет приоритет над вычисленным: он уже уехал в
		// выданные ссылки как SNI, и пересчёт при изменении пула убил бы их все
		dest := set.DestFor(nodeID)
		if node, err := s.reg.Get(nodeID); err == nil {
			// Цель, переставшая быть правдоподобной для российского юзера,
			// переназначается несмотря на закрепление: SNI видит цензор, и
			// странный домен выдаёт ноду сам по себе
			if node.RealityDest != "" && scan.PlausibleSNI(node.RealityDest) {
				dest = node.RealityDest
			} else if dest != "" {
				_ = s.reg.SetDest(nodeID, dest)
			}
		}
		if dest != "" && out.GetReality() != nil {
			out.Reality.Dest = dest
			out.Reality.ServerNames = []string{hostOfDest(dest)}
		}
	}
	node, err := s.reg.Get(nodeID)
	if err != nil {
		return out
	}
	for i, in := range out.GetInbounds() {
		in.AcceptProxyProtocol = node.BehindProxy
		if i < len(node.OfferedPorts) && node.OfferedPorts[i] != 0 {
			in.Port = node.OfferedPorts[i]
		}
		if !node.BehindProxy || node.PublicPort == 0 {
			continue
		}
		// Прокси разбирает соединения по SNI и отдаёт их одному инбаунду. Второй
		// транспорт с тем же именем ему не различить, поэтому он открыт своим
		// портом напрямую, а через прокси идёт только первый
		if proxied(out, in) {
			in.AcceptProxyProtocol = true
			in.PublicPort = node.PublicPort
			continue
		}
		in.AcceptProxyProtocol = false
		in.PublicPort = in.GetPort()
	}
	return out
}

func (s *Server) currentConfig() *fedpb.NodeConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nodeConfig
}

// New builds a server around an existing registry
func New(reg *registry.Registry, tokens EnrollTokens, headEndpoint string) *Server {
	return &Server{
		reg:               reg,
		tokens:            tokens,
		headEndpoint:      headEndpoint,
		heartbeatInterval: 5 * time.Second,
		statsInterval:     time.Second,
		agg:               aggregator.New(),
		probes:            make(map[string]ProbeInfo),
		sessions:          make(map[string]*session),
		pending:           newPending(),
	}
}

// Aggregator exposes the live numbers the panel and the public counter read
func (s *Server) Aggregator() *aggregator.Aggregator { return s.agg }

// SetRealityCandidates sets the dest:port list agents probe locally. The head
// owns the list because it should be curated centrally; the agent owns the
// verdict because a target that is fast from one country can be censored from
// another
func (s *Server) SetRealityCandidates(targets []string) {
	s.realityCandidates = append([]string(nil), targets...)
}

func newSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Join enrolls a node against a single-use token. It is separate from Session
// because it authenticates with a different credential: the enroll token, which
// the node does not keep, rather than the node secret, which it does
func (s *Server) Join(ctx context.Context, req *fedpb.JoinRequest) (*fedpb.JoinResponse, error) {
	token := strings.TrimSpace(req.GetEnrollToken())
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "missing enroll token")
	}
	// Somebody always pastes the placeholder from the docs
	if strings.HasPrefix(token, "<") && strings.HasSuffix(token, ">") {
		return nil, status.Error(codes.InvalidArgument, "enroll token is a placeholder, paste the real one")
	}
	if strings.TrimSpace(req.GetNodeFingerprint()) == "" {
		return nil, status.Error(codes.InvalidArgument, "missing node fingerprint")
	}
	donorID, err := s.tokens.Redeem(token)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "enroll token rejected")
	}
	nodeID, err := newSecret()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	secret, err := newSecret()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	node := &registry.Node{
		ID:                  nodeID[:32],
		Fingerprint:         req.GetNodeFingerprint(),
		Secret:              secret,
		DonorID:             donorID,
		Passport:            req.GetPassport(),
		DeclaredBudgetBytes: req.GetDeclaredMonthlyBudgetBytes(),
		OfferedPorts:        req.GetOfferedPorts(),
		BehindProxy:         req.GetBehindProxy(),
		PublicPort:          req.GetPublicPort(),
		// A node is not usable until the head has proved for itself that it is
		// reachable; a self-reported address proves nothing behind NAT
		State:  fedpb.RotationState_ROTATION_STATE_PARKED,
		Reason: "awaiting head reachability probe",
	}
	s.reg.Add(node)
	log.Printf("fedserver: node %s enrolled for donor %s (%s)", node.ID, donorID, req.GetPassport().GetHostname())

	return &fedpb.JoinResponse{
		NodeId:              node.ID,
		NodeSecret:          secret,
		HeadEndpoint:        s.headEndpoint,
		HeartbeatIntervalMs: uint32(s.heartbeatInterval.Milliseconds()),
		StatsIntervalMs:     uint32(s.statsInterval.Milliseconds()),
		RealityCandidates:   s.realityCandidates,
	}, nil
}

// authFromMetadata pulls the node id and secret an agent presents on its stream
func authFromMetadata(ctx context.Context) (id, secret string, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", errors.New("no metadata")
	}
	get := func(key string) string {
		if v := md.Get(key); len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	id, secret = get("wingsv-node-id"), get("wingsv-node-secret")
	if id == "" || secret == "" {
		return "", "", errors.New("missing node credentials")
	}
	return id, secret, nil
}

// Session is the one long-lived stream carrying heartbeats, stats and acks up,
// and config and commands down. Everything rides here rather than in separate
// unary calls: on third-party servers behind hostile NAT, every extra dial is
// another failure mode
func (s *Server) Session(stream fedpb.Federation_SessionServer) error {
	id, secret, err := authFromMetadata(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	node, err := s.reg.Authenticate(id, secret)
	if err != nil {
		return status.Error(codes.Unauthenticated, "node credentials rejected")
	}
	log.Printf("fedserver: session opened for node %s", node.ID)
	defer log.Printf("fedserver: session closed for node %s", node.ID)

	sess := s.register(node.ID)
	defer s.deregister(node.ID, sess)

	// One goroutine owns Send. A gRPC stream is not safe for concurrent sends,
	// and commands now arrive from the rotation loop as well as from this loop
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-sess.done:
				sendErr <- nil
				return
			case <-stream.Context().Done():
				sendErr <- nil
				return
			case frame := <-sess.out:
				if err := stream.Send(frame); err != nil {
					sendErr <- err
					return
				}
			}
		}
	}()

	for {
		select {
		case err := <-sendErr:
			return err
		default:
		}
		frame, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || stream.Context().Err() != nil {
				return nil
			}
			return err
		}
		switch payload := frame.GetFrame().(type) {
		case *fedpb.AgentFrame_Hello:
			s.reg.Touch(node.ID)
			if p := payload.Hello.GetPassport(); p != nil {
				if err := s.reg.SetPassport(node.ID, p); err != nil {
					log.Printf("fedserver: node %s passport not stored: %v", node.ID, err)
				}
			}
			log.Printf("fedserver: node %s hello agent=%s xray=%s vktp=%s config=%d",
				node.ID, payload.Hello.GetAgentVersion(), payload.Hello.GetXrayVersion(),
				payload.Hello.GetVktpVersion(), payload.Hello.GetConfigVersion())
			// Пушим то, что предназначено ЭТОЙ ноде, а не общий конфиг: порты и
			// заимствованная tls-личность у каждой свои, и общий конфиг сажал
			// весь флот на одну пару портов - ровно ту, которую нода занять не
			// может.
			//
			// Только когда нода отстала: повторная отправка уже применённого
			// конфига перезапускает Xray и рвёт живые соединения
			if cfg := s.ConfigFor(node.ID); cfg != nil && cfg.GetVersion() != payload.Hello.GetConfigVersion() {
				if err := sess.send(&fedpb.HeadFrame{
					Frame: &fedpb.HeadFrame_ConfigPush{ConfigPush: cfg},
				}); err != nil {
					return err
				}
			}
			// Reconcile. A profile revoked while this node was unreachable was
			// simply lost, and a node that comes back still serving somebody who
			// was moved off it is traffic nobody is accounting for
			if specs, ok := s.currentProfiles(node.ID); ok {
				if err := sess.send(&fedpb.HeadFrame{
					Frame: &fedpb.HeadFrame_ProfileDelta{ProfileDelta: &fedpb.ProfileDelta{
						Add: specs, Replace: true,
					}},
				}); err != nil {
					return err
				}
			}
		case *fedpb.AgentFrame_Heartbeat:
			beat := payload.Heartbeat
			if err := s.reg.ApplyHeartbeatWithBuilds(node.ID, beat.GetCpuPct(), beat.GetUptimeSeconds(),
				beat.GetXrayState(), beat.GetVktpState(),
				beat.GetXrayVersion(), beat.GetVktpVersion()); err != nil {
				log.Printf("fedserver: heartbeat from %s: %v", node.ID, err)
			}
			s.reg.SetRelayEndpoint(node.ID, beat.GetRelayEndpoint())
			// Релей с чужим бэкендом уносит расшифрованный трафик мимо
			// наблюдения и мимо шейпера, поэтому это претензия к ноде, а не
			// просто факт
			if sink := s.relayModeSink(); sink != nil && beat.GetVktpState() != "unreachable" {
				sink(node.ID, beat.GetRelayFederation())
			}
		case *fedpb.AgentFrame_Stats:
			sample := payload.Stats
			if _, err := s.reg.ApplySample(node.ID, sample.GetBootId(),
				sample.GetTotalUpBytes(), sample.GetTotalDownBytes(), sample.GetProbeBytes()); err != nil {
				log.Printf("fedserver: sample from %s: %v", node.ID, err)
			}
			s.reg.SetSessions(node.ID, sample.GetActiveSessions())
			if s.usage != nil {
				for _, p := range sample.GetProfiles() {
					s.usage.AddUsage(p.GetProfileId(), p.GetTransport(), p.GetUpDeltaBytes(), p.GetDownDeltaBytes())
				}
				// Пиры релея приходят по ключу: кто за ним стоит, знает только
				// башка, потому что провижн выдавала она
				s.applyPeerUsage(sample.GetPeers())
			}
			s.agg.Ingest(aggregator.Sample{
				NodeID:         node.ID,
				DonorID:        node.DonorID,
				BootID:         sample.GetBootId(),
				UpBytes:        sample.GetTotalUpBytes(),
				DownBytes:      sample.GetTotalDownBytes(),
				ProbeBytes:     sample.GetProbeBytes(),
				ActiveSessions: sample.GetActiveSessions(),
				ActiveStreams:  sample.GetActiveStreams(),
				At:             sampleTime(sample.GetUnixMs()),
			})
		case *fedpb.AgentFrame_ConfigAck:
			ack := payload.ConfigAck
			if !ack.GetOk() {
				log.Printf("fedserver: node %s rejected config %d: %s",
					node.ID, ack.GetConfigVersion(), ack.GetError())
				break
			}
			if err := s.reg.SetIdentity(node.ID, ack.GetRealityPublicKey(), ack.GetMldsa65Verify()); err != nil {
				log.Printf("fedserver: identity from %s: %v", node.ID, err)
			}
			log.Printf("fedserver: node %s applied config %d, inbounds=%v reality_pub=%s",
				node.ID, ack.GetConfigVersion(), ack.GetEffectiveInbounds(), ack.GetRealityPublicKey())
		case *fedpb.AgentFrame_Abuse:
			// A class and a count, never a destination. The node classified it
			// locally precisely so nobody's browsing reaches the head
			if sink := s.abuseSink(); sink != nil {
				sink(payload.Abuse, node.ID)
			}
			log.Printf("fedserver: node %s reports %s on profile %s (count %d)",
				node.ID, payload.Abuse.GetKind(), payload.Abuse.GetProfileId(), payload.Abuse.GetCount())
		case *fedpb.AgentFrame_Receipts:
			// Клиент не дотянулся до панели и отдал расписки ноде. Нода тут
			// курьер: подпись клиентская, и всё, что нода могла бы наврать,
			// проверяется на общих основаниях
			if sink := s.receiptSink(); sink != nil {
				sink(payload.Receipts.GetReceipts())
			}
		case *fedpb.AgentFrame_Domains:
			// Сырьё, а не класс. Бесплатный доступ без разбора трафика сжирают
			// фермы и скамеры, поэтому смотрим плотно, но храним ограниченный
			// срок и только по профилям федерации
			if sink := s.domainSink(); sink != nil {
				sink(payload.Domains, node.ID)
			}
			if dropped := payload.Domains.GetDropped(); dropped > 0 {
				log.Printf("fedserver: node %s dropped %d observations before they could be sent", node.ID, dropped)
			}
		case *fedpb.AgentFrame_FetchResult:
			// Нода принесла то, за чем её посылали. Ответ на просроченный
			// запрос выбросится сам: ждать его уже некому
			s.pending.deliver(payload.FetchResult)
		case *fedpb.AgentFrame_Alarm:
			log.Printf("fedserver: node %s alarm %s/%s: %s", node.ID,
				payload.Alarm.GetLevel(), payload.Alarm.GetCode(), payload.Alarm.GetMessage())
		}
	}
}

// probeRefresh is how often an open vantage point is re-sent its target list
const probeRefresh = time.Minute

// ProbeSession serves a vantage point inside the censored network. Its reports
// are the only trustworthy statement about whether a node is usable, because a
// node can be healthy from the head's own network and dead from where the users
// are - and, more often, neither dead nor healthy but shaped
func (s *Server) ProbeSession(stream fedpb.Federation_ProbeSessionServer) error {
	targetsOf, ingest := s.probeFleet()
	var probeID string

	// Targets are re-sent on a timer as well as on hello: the fleet changes under
	// a long-lived probe, and a vantage point measuring a node that left rotation
	// is spending a donor's traffic on nothing
	refresh := time.NewTicker(probeRefresh)
	defer refresh.Stop()
	wake := s.addProbeWake()
	defer s.dropProbeWake(wake)
	frames := make(chan *fedpb.ProbeFrame)
	errs := make(chan error, 1)
	go func() {
		for {
			frame, err := stream.Recv()
			if err != nil {
				errs <- err
				return
			}
			frames <- frame
		}
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-errs:
			if probeID != "" {
				log.Printf("fedserver: probe %s offline", probeID)
			}
			return nil
		case <-refresh.C:
			if probeID == "" || targetsOf == nil {
				continue
			}
			if err := stream.Send(targetsOf()); err != nil {
				return err
			}
		case <-wake:
			// Оператор попросил замерить сейчас, не дожидаясь круга
			if probeID == "" || targetsOf == nil {
				continue
			}
			task := targetsOf()
			task.MeasureNow = true
			if err := stream.Send(task); err != nil {
				return err
			}
		case frame := <-frames:
			switch payload := frame.GetFrame().(type) {
			case *fedpb.ProbeFrame_Hello:
				probeID = payload.Hello.GetProbeId()
				s.mu.Lock()
				s.probes[probeID] = ProbeInfo{
					ID:       probeID,
					Region:   payload.Hello.GetRegion(),
					ISP:      payload.Hello.GetIsp(),
					ASN:      payload.Hello.GetAsn(),
					Version:  payload.Hello.GetAgentVersion(),
					LastSeen: time.Now(),
				}
				s.mu.Unlock()
				log.Printf("fedserver: probe %s online from %s/%s", probeID,
					payload.Hello.GetRegion(), payload.Hello.GetAsn())
				if targetsOf != nil {
					if err := stream.Send(targetsOf()); err != nil {
						return err
					}
				}
			case *fedpb.ProbeFrame_Report:
				r := payload.Report
				if ingest != nil {
					ingest(probeID, r)
				}
				if !r.GetHandshakeOk() {
					// The reason matters more than the verdict: an operator has
					// to be able to tell a blocked node from a broken probe
					log.Printf("fedserver: probe %s node=%s addr=%s transport=%s failed: %s",
						probeID, r.GetNodeId(), r.GetAddress(), r.GetTransport(), r.GetError())
					break
				}
				log.Printf("fedserver: probe %s node=%s addr=%s transport=%s down=%d bps rtt=%dms",
					probeID, r.GetNodeId(), r.GetAddress(), r.GetTransport(),
					r.GetDownloadBps(), r.GetRttMs())
			case *fedpb.ProbeFrame_Heartbeat:
				s.mu.Lock()
				seen := s.probes[probeID]
				seen.ID, seen.LastSeen = probeID, time.Now()
				s.probes[probeID] = seen
				s.mu.Unlock()
			}
		}
	}
}

// ProbesOnline lists the vantage points reporting recently. A federation with no
// probe has no verified address for anything, which is a state worth seeing
func (s *Server) ProbesOnline(within time.Duration) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]string, 0, len(s.probes))
	for id, info := range s.probes {
		if now.Sub(info.LastSeen) <= within {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// addProbeWake регистрирует канал ручного запуска для одной открытой сессии
func (s *Server) addProbeWake() chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.probeWake = append(s.probeWake, ch)
	s.mu.Unlock()
	return ch
}

func (s *Server) dropProbeWake(ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, cur := range s.probeWake {
		if cur == ch {
			s.probeWake = append(s.probeWake[:i], s.probeWake[i+1:]...)
			return
		}
	}
}

// WakeProbes просит все открытые точки наблюдения замерить прямо сейчас и
// возвращает, скольких удалось попросить. Круг идёт раз в пять минут, и без
// этого проверить свежую ноду руками нечем
func (s *Server) WakeProbes() uint32 {
	s.mu.Lock()
	channels := append([]chan struct{}(nil), s.probeWake...)
	s.mu.Unlock()
	var woken uint32
	for _, ch := range channels {
		select {
		case ch <- struct{}{}:
			woken++
		default:
			// Уже разбужен и ещё не дошёл до цикла
			woken++
		}
	}
	return woken
}

// ProbeInfo is one vantage point as it introduced itself
type ProbeInfo struct {
	ID       string
	Region   string
	ISP      string
	ASN      string
	Version  string
	LastSeen time.Time
}

// Probes lists every vantage point seen since the head started, online or not:
// точка наблюдения, которая замолчала, - сама по себе новость
func (s *Server) Probes() []ProbeInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ProbeInfo, 0, len(s.probes))
	for _, info := range s.probes {
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// sampleTime trusts the agent's clock only for spacing samples apart. A skewed
// or zero clock falls back to arrival time, which is never worse than a rate
// computed against a bogus interval
func sampleTime(unixMs int64) time.Time {
	if unixMs <= 0 {
		return time.Time{}
	}
	at := time.UnixMilli(unixMs)
	if d := time.Since(at); d > time.Minute || d < -time.Minute {
		return time.Time{}
	}
	return at
}

// proxied говорит, какой инбаунд стоит за прокси: первый REALITY-инбаунд в
// конфиге, обычно tcp
func proxied(cfg *fedpb.NodeConfig, in *fedpb.InboundSpec) bool {
	for _, candidate := range cfg.GetInbounds() {
		if candidate.GetReality() {
			return candidate == in
		}
	}
	return false
}

// hostOfDest strips the port: serverNames carries a name, not an endpoint
func hostOfDest(dest string) string {
	if host, _, err := net.SplitHostPort(dest); err == nil {
		return host
	}
	return dest
}
