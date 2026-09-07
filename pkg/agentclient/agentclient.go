// Package agentclient is the public half of the agent: enrollment plus the
// session loop that keeps a node talking to the head.
//
// It is public on purpose. The WINGS-N/3x-ui fork joins the federation by
// implementing Executor over its own Xray plumbing and calling Run, rather than
// carrying a second copy of the agent. Everything the fork needs must therefore
// stay out of internal/ and keep a stable signature
package agentclient

import (
	"context"
	"errors"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/dialpick"
)

// Executor is everything the session loop needs from whatever actually runs the
// traffic. The standalone agent implements it over its own supervisor; the 3x-ui
// fork implements it over inbound rows and its Xray service.
//
// No method may block for long: the loop calls them from the receive path, and a
// stalled ApplyConfig stalls heartbeats too
type Executor interface {
	// ApplyConfig makes the node serve what the head asked for, returning the
	// inbound tags that ended up live
	ApplyConfig(ctx context.Context, cfg *fedpb.NodeConfig) (effective []string, err error)
	// ApplyProfiles adds and removes users. A profile needs one entry per inbound
	// because the vision flow cannot be shared between the tcp and xhttp inbounds.
	// The whole delta is passed rather than two slices because it also carries
	// replace, which makes the add list authoritative
	ApplyProfiles(ctx context.Context, delta *fedpb.ProfileDelta) error
	// Sample returns cumulative counters, never deltas: the head derives rates
	// itself so a dropped sample costs nothing
	Sample(ctx context.Context) (*fedpb.StatsSample, error)
	// Health is the liveness snapshot sent on the heartbeat cadence
	Health(ctx context.Context) (*fedpb.Heartbeat, error)
	// SetRotationState reacts to the head parking or draining this node
	SetRotationState(state fedpb.RotationState) error
}

// Upgrader is implemented by an executor that can fetch a build or restart what
// it already runs. Optional: an agent that does not implement it simply ignores
// the command instead of failing the session over it.
type Upgrader interface {
	Upgrade(ctx context.Context, component, version, url, sha512 string, restartOnly bool) error
}

// ConfigVersioner is implemented by an executor that remembers which config it
// has applied. Without it every reconnect looks like a fresh node to the head,
// which re-pushes the config and restarts Xray - dropping the donor's own
// clients for nothing
type ConfigVersioner interface {
	ConfigVersion() uint64
}

// Componenter is implemented by an executor that knows which builds it runs.
// Без него башка видит пустые версии и не может сказать, доехало ли обновление
type Componenter interface {
	ComponentVersions() (xray string, vktp string)
}

// AbuseReporter is implemented by an executor that watches for abuse. Optional:
// an executor that reports nothing simply never accuses anybody
type AbuseReporter interface {
	// DrainAbuse hands over what has been seen since the last call. It must only
	// ever describe metered federation profiles
	DrainAbuse() []*fedpb.AbuseSignal
}

// ReceiptCarrier is implemented by an executor that takes signed receipts from
// clients sitting in its own tunnel and hands them on.
//
// Нода тут только курьер: расписку подписал клиент, подделать её она не может, а
// пропустить мимо себя не в её интересах - молчание превращается в overclaim
type ReceiptCarrier interface {
	// DrainReceipts отдаёт то, что принесли клиенты. nil, когда не приносили
	DrainReceipts() []*fedpb.TrafficReceipt
}

// DomainReporter is implemented by an executor that watches where traffic goes.
// Как и AbuseReporter, касается ТОЛЬКО профилей федерации
type DomainReporter interface {
	// DrainDomains отдаёт свёрнутое окно. nil, когда за окно не было нихуя
	DrainDomains() *fedpb.DomainBatch
}

// IdentityReporter is implemented by an executor that owns a REALITY identity.
// Only the public halves travel; without them the head cannot build a share link
type IdentityReporter interface {
	PublicIdentity() (publicKey, mldsa65Verify string)
}

// Config is what the loop needs to reach and authenticate with the head
type Config struct {
	HeadEndpoint string
	NodeID       string
	NodeSecret   string
	BootID       string
	AgentVersion string
	// Passport едет с каждым hello: адреса ноды меняются, а зачисление бывает
	// один раз за её жизнь
	Passport *fedpb.NodePassport

	HeartbeatInterval time.Duration
	StatsInterval     time.Duration

	// Dial lets a caller supply its own transport credentials. Left nil, the
	// caller is expected to have configured them on the connection it passes in
	Dial func(ctx context.Context, endpoint string) (*grpc.ClientConn, error)
}

func (c *Config) applyDefaults() {
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 5 * time.Second
	}
	if c.StatsInterval <= 0 {
		c.StatsInterval = time.Second
	}
}

// statsQueueDepth is small on purpose. Stats are a snapshot of cumulative
// counters, so a backlog has no value: the newest sample makes every older one
// redundant. Dropping keeps a slow link from stalling the heartbeat path
const statsQueueDepth = 4

// Run keeps a session open until ctx is cancelled, reconnecting with backoff.
//
// A dropped stream is normal on third-party servers, so the loop treats it as a
// pause rather than an error: it re-dials, re-sends Hello with the config
// version it already has, and the head re-pushes config only if that differs
func Run(ctx context.Context, cfg Config, ex Executor) error {
	cfg.applyDefaults()
	if cfg.Dial == nil {
		return errors.New("agentclient: no dialer configured")
	}
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	// A session that ran for a while and then dropped is a head being
	// redeployed, not a head that is gone. Growing the delay in that case pushes
	// every node into a minute of silence over a restart that took ten seconds,
	// so the backoff resets whenever the stream had actually been working.
	const settled = 90 * time.Second
	picker := dialpick.New(cfg.HeadEndpoint)
	for {
		startedAt := time.Now()
		err := runOnce(ctx, cfg, ex, picker)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(startedAt) >= settled {
			backoff = 2 * time.Second
		}
		if err != nil {
			log.Printf("agentclient: session ended: %v (retrying in %s)", err, backoff)
			// Jitter matters: a head restart otherwise brings the whole fleet
			// back in lockstep and the reconnect storm looks like an outage
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff + jitter):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		backoff = 2 * time.Second
	}
}

func runOnce(ctx context.Context, cfg Config, ex Executor, picker *dialpick.Picker) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Имя башки стоит за балансировщиком, и тот иногда отдаёт узел, до
	// которого из сети ноды не достучаться. Перебираем адреса сами, а рабочий
	// держим, пока балансировщик его отдаёт
	endpoint := picker.Next(ctx)
	conn, err := cfg.Dial(ctx, endpoint)
	if err != nil {
		picker.Failed(endpoint)
		return err
	}
	defer func() { _ = conn.Close() }()

	ctx = metadata.AppendToOutgoingContext(ctx,
		"wingsv-node-id", cfg.NodeID,
		"wingsv-node-secret", cfg.NodeSecret,
	)
	stream, err := fedpb.NewFederationClient(conn).Session(ctx)
	if err != nil {
		picker.Failed(endpoint)
		return err
	}

	var configVersion uint64
	if versioner, ok := ex.(ConfigVersioner); ok {
		configVersion = versioner.ConfigVersion()
	}
	var xrayVersion, vktpVersion string
	if components, ok := ex.(Componenter); ok {
		xrayVersion, vktpVersion = components.ComponentVersions()
	}
	if err := stream.Send(&fedpb.AgentFrame{Frame: &fedpb.AgentFrame_Hello{Hello: &fedpb.Hello{
		NodeId:        cfg.NodeID,
		BootId:        cfg.BootID,
		AgentVersion:  cfg.AgentVersion,
		ConfigVersion: configVersion,
		XrayVersion:   xrayVersion,
		VktpVersion:   vktpVersion,
		Passport:      cfg.Passport,
	}}}); err != nil {
		return err
	}

	// Stats go through a lossy queue; heartbeats, acks and alarms take the
	// direct path so a saturated link can never silence liveness
	stats := make(chan *fedpb.StatsSample, statsQueueDepth)
	sendErr := make(chan error, 1)
	go func() { sendErr <- pump(ctx, cfg, ex, stream, stats) }()
	go collectStats(ctx, cfg, ex, stats)

	for {
		frame, err := stream.Recv()
		if err != nil {
			select {
			case pumpErr := <-sendErr:
				if pumpErr != nil {
					return pumpErr
				}
			default:
			}
			return err
		}
		switch payload := frame.GetFrame().(type) {
		case *fedpb.HeadFrame_ConfigPush:
			cfgPush := payload.ConfigPush
			effective, applyErr := ex.ApplyConfig(ctx, cfgPush)
			ack := &fedpb.ConfigAck{
				ConfigVersion:     cfgPush.GetVersion(),
				Ok:                applyErr == nil,
				AppliedUnix:       time.Now().Unix(),
				EffectiveInbounds: effective,
			}
			if applyErr != nil {
				ack.Error = applyErr.Error()
			} else if reporter, ok := ex.(IdentityReporter); ok {
				ack.RealityPublicKey, ack.Mldsa65Verify = reporter.PublicIdentity()
			}
			if err := stream.Send(&fedpb.AgentFrame{Frame: &fedpb.AgentFrame_ConfigAck{ConfigAck: ack}}); err != nil {
				return err
			}
		case *fedpb.HeadFrame_ProfileDelta:
			if err := ex.ApplyProfiles(ctx, payload.ProfileDelta); err != nil {
				_ = stream.Send(&fedpb.AgentFrame{Frame: &fedpb.AgentFrame_Alarm{Alarm: &fedpb.Alarm{
					Level: "error", Code: "profiles", Message: err.Error(),
				}}})
			}
		case *fedpb.HeadFrame_Fetch:
			// Башке прикрыли IP, и она просит сходить наружу вместо неё. Адрес
			// у ноды свой, так что оттуда видно то, что башке уже нихуя не
			// видно. Отвечаем всегда, даже отказом: молчание она отличить от
			// потерянного кадра не может и будет ждать вечно
			go func(req *fedpb.FetchRequest) {
				result := fetchFor(ctx, req)
				if err := stream.Send(&fedpb.AgentFrame{
					Frame: &fedpb.AgentFrame_FetchResult{FetchResult: result},
				}); err != nil {
					log.Printf("agentclient: fetch result not sent: %v", err)
				}
			}(payload.Fetch)
		case *fedpb.HeadFrame_Rotation:
			_ = ex.SetRotationState(payload.Rotation.GetState())
		case *fedpb.HeadFrame_Upgrade:
			// Не рвём сессию, если исполнитель этого не умеет: команда
			// операторская, а нода должна продолжать обслуживать людей
			up, ok := ex.(Upgrader)
			if !ok {
				log.Printf("agentclient: upgrade command ignored, this agent cannot act on it")
				break
			}
			cmd := payload.Upgrade
			if err := up.Upgrade(ctx, cmd.GetComponent(), cmd.GetVersion(),
				cmd.GetUrl(), cmd.GetSha512(), cmd.GetRestartOnly()); err != nil {
				log.Printf("agentclient: %s upgrade failed: %v", cmd.GetComponent(), err)
			}
		}
	}
}

func pump(ctx context.Context, cfg Config, ex Executor, stream fedpb.Federation_SessionClient, stats <-chan *fedpb.StatsSample) error {
	beat := time.NewTicker(cfg.HeartbeatInterval)
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case sample := <-stats:
			if err := stream.Send(&fedpb.AgentFrame{Frame: &fedpb.AgentFrame_Stats{Stats: sample}}); err != nil {
				return err
			}
		case <-beat.C:
			if reporter, ok := ex.(AbuseReporter); ok {
				for _, signal := range reporter.DrainAbuse() {
					if err := stream.Send(&fedpb.AgentFrame{
						Frame: &fedpb.AgentFrame_Abuse{Abuse: signal},
					}); err != nil {
						return err
					}
				}
			}
			if carrier, ok := ex.(ReceiptCarrier); ok {
				if receipts := carrier.DrainReceipts(); len(receipts) > 0 {
					if err := stream.Send(&fedpb.AgentFrame{
						Frame: &fedpb.AgentFrame_Receipts{
							Receipts: &fedpb.ReceiptBatch{Receipts: receipts},
						},
					}); err != nil {
						return err
					}
				}
			}
			if reporter, ok := ex.(DomainReporter); ok {
				if batch := reporter.DrainDomains(); batch != nil {
					if err := stream.Send(&fedpb.AgentFrame{
						Frame: &fedpb.AgentFrame_Domains{Domains: batch},
					}); err != nil {
						return err
					}
				}
			}
			health, err := ex.Health(ctx)
			if err != nil {
				continue
			}
			if err := stream.Send(&fedpb.AgentFrame{Frame: &fedpb.AgentFrame_Heartbeat{Heartbeat: health}}); err != nil {
				return err
			}
		}
	}
}

// collectStats needs the channel in both directions: when the queue is full it
// discards the oldest sample to make room for the newest
func collectStats(ctx context.Context, cfg Config, ex Executor, out chan *fedpb.StatsSample) {
	tick := time.NewTicker(cfg.StatsInterval)
	defer tick.Stop()
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			sample, err := ex.Sample(ctx)
			if err != nil || sample == nil {
				continue
			}
			seq++
			sample.Seq = seq
			sample.BootId = cfg.BootID
			sample.UnixMs = time.Now().UnixMilli()
			select {
			case out <- sample:
			default:
				// Queue full: drop the oldest and keep the newest, because a
				// stale cumulative counter tells the head nothing the fresh one
				// does not already say
				select {
				case <-out:
				default:
				}
				select {
				case out <- sample:
				default:
				}
			}
		}
	}
}

// fetchDefaults - потолки на случай, если башка их не назвала
const (
	fetchDefaultTimeout = 20 * time.Second
	fetchDefaultMaxBody = 1 << 20
)

// fetchFor ходит за телом по просьбе башки.
//
// Нода тут просто почтальон: ни во что не вникает, тело отдаёт как есть, а
// разбирается с ним башка. Потолок по размеру обязателен - иначе в ответ
// прилетит гигабайт, и мы сожрём память донора ни за что
func fetchFor(ctx context.Context, req *fedpb.FetchRequest) *fedpb.FetchResult {
	out := &fedpb.FetchResult{Id: req.GetId()}
	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = fetchDefaultTimeout
	}
	limit := int64(req.GetMaxBytes())
	if limit <= 0 {
		limit = fetchDefaultMaxBody
	}

	call, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(call, http.MethodGet, req.GetUrl(), nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for key, value := range req.GetHeaders() {
		httpReq.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer func() { _ = resp.Body.Close() }()
	out.Status = uint32(resp.StatusCode)
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Body = body
	return out
}
