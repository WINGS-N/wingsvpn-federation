// Package supervisor turns a NodeConfig from the head into a running node.
//
// The order is not negotiable: fetch the binaries, then mint keys with the
// binary that just landed, then render the config that needs those keys, then
// start. Doing any of it earlier means generating keys with a binary that is not
// there yet
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	fedpb "wingsnet.org/federation/gen/fedpb"

	"wingsnet.org/federation/internal/agent/abusewatch"
	"wingsnet.org/federation/internal/agent/binfetch"
	"wingsnet.org/federation/internal/agent/domainwatch"
	"wingsnet.org/federation/internal/agent/geo"
	"wingsnet.org/federation/internal/agent/portgate"
	"wingsnet.org/federation/internal/agent/portpick"
	"wingsnet.org/federation/internal/agent/realitykeys"
	"wingsnet.org/federation/internal/agent/receiptdoor"
	"wingsnet.org/federation/internal/agent/shaper"
	"wingsnet.org/federation/internal/agent/vktpctl"
	"wingsnet.org/federation/internal/agent/xrayapi"
	"wingsnet.org/federation/internal/agent/xraycfg"
	"wingsnet.org/federation/internal/agent/xrayproc"
)

// Options wires the supervisor to its surroundings
type Options struct {
	BinDir    string
	ConfigDir string
	StateDir  string

	// XrayURL and RelayURL are where binaries come from, with the digests the
	// head pinned. An empty digest means the head did not pin a build
	XrayURL      string
	XraySHA512   string
	RelayURL     string
	RelaySHA512  string
	RelayGRPC    string
	RelayToken   string
	SkipDownload bool
}

// Supervisor implements agentclient.Executor over real processes
type Supervisor struct {
	opts Options

	mu       sync.Mutex
	keys     realitykeys.Pair
	xray     *xrayproc.Process
	api      *xrayapi.Client
	relay    *vktpctl.Client
	profiles []xraycfg.Profile
	version  uint64
	rotation fedpb.RotationState
	started  time.Time
	// wantXrayVersion - что оператор выбрал для флота, autoUpgrade - можно ли
	// ставить это самому. Перезапуск рвёт живые соединения, поэтому по умолчанию
	// нода только сообщает о расхождении
	wantXrayVersion string
	autoUpgrade     bool

	abuse           *abusewatch.Watcher
	lastAbuseSample time.Time
	// domains слушает ядро постоянно, а не по таймеру: событие приходит на
	// закрытии соединения, и опрашивать тут нечего
	domains       *domainwatch.Watcher
	domainsCancel context.CancelFunc
	geoDB         *geo.DB
	country       *geo.CountryResolver

	// The core zeroes its counters on restart. Carrying the previous run keeps
	// the reported total from walking backwards, which would otherwise refund the
	// donor traffic they already spent
	xrayCarry xrayapi.Counter
	xrayLast  xrayapi.Counter
	// Доля проверок в перенесённом счёте. Без неё зондовый трафик прошлого
	// запуска становится обычным, и нода выглядит так, будто навозила людям
	probeCarry uint64
	probeLast  uint64
	// probeEmails - все учётки зондов, что стояли на ноде. Список профилей
	// живёт ровно пока профиль на инбаунде, а счётчик ядра держит его и после
	// снятия: забыв имя, мы записали бы чужие замеры в трафик донора
	probeEmails map[string]struct{}
	// profileLast - последние счётчики по каждому профилю. Башке уходят дельты:
	// профиль живёт меньше ноды, и кумулятивная цифра по нему ничего не значит
	// после того, как его сняли с инбаунда
	profileLast map[string]xrayapi.Counter
	// peerLast - прошлые счётчики пиров релея, чтобы считать дельту
	peerLast map[string]vktpctl.Peer
	// shaper режет скорость пиров: у релея ограничителя нет
	shaper *shaper.Shaper
	// peerProfiles - какой адрес в туннеле чей, потому что с wg видно только
	// адрес и больше нихуя
	peerProfiles map[string]string
	// receipts - дверь для клиентов, которым до панели снаружи не достучаться
	receipts *receiptdoor.Door
}

// New builds a supervisor that has not started anything yet
func New(opts Options) *Supervisor {
	s := &Supervisor{
		opts:    opts,
		api:     xrayapi.NewLocal(xraycfg.APIPort),
		started: time.Now(),
	}
	s.abuse = abusewatch.New(s.api, s)
	s.domains = domainwatch.New(s)
	// Резолвер живёт и без локальной базы: внешние справочники отвечают сами по
	// себе, а база к ним добавляется, когда доедет
	s.country = geo.NewCountryResolver(nil)
	return s
}

// StartGeo качает базы и включает гео-сигнал. Ошибка не мешает ноде работать:
// без баз остаётся счёт адресов
func (s *Supervisor) StartGeo(ctx context.Context, keys geo.Keys) error {
	set, err := geo.Fetch(ctx, filepath.Join(s.opts.StateDir, "geo"), keys)
	if err != nil {
		return err
	}
	db, err := geo.Open(set)
	if err != nil {
		return err
	}
	if s.geoDB != nil {
		_ = s.geoDB.Close()
	}
	s.geoDB = db
	s.country = geo.NewCountryResolver(db)
	s.abuse.SetPlaces(db)
	return nil
}

// ErrNoBinary means the config needs a binary that is neither installed nor
// fetchable
var ErrNoBinary = errors.New("supervisor: xray binary is not available")

// ErrNoRelay means this node carries Xray only, with no relay to talk to.
var ErrNoRelay = errors.New("supervisor: no relay control connection")

// ErrRelayRestart says the relay re-read what it could and the rest needs a
// process restart - which belongs to whoever started it, not to the agent.
var ErrRelayRestart = errors.New("supervisor: the relay needs a restart for")

func (s *Supervisor) xrayPath() string { return filepath.Join(s.opts.BinDir, "xray") }

func (s *Supervisor) configPath() string { return filepath.Join(s.opts.ConfigDir, "xray.json") }

func (s *Supervisor) keyPath() string { return filepath.Join(s.opts.StateDir, "reality.key") }

func (s *Supervisor) appliedPath() string { return filepath.Join(s.opts.StateDir, "applied.toml") }

// configSchema - ревизия того, как агент собирает конфиг Xray. Растёт, когда
// меняется сама сборка: нода тогда просит конфиг заново, вместо того чтобы
// вечно жить с тем, что сгенерил предыдущий агент
const configSchema = 2

// ConfigVersion is what the session loop reports in Hello
func (s *Supervisor) ConfigVersion() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version == 0 {
		s.version = loadAppliedVersion(s.appliedPath())
	}
	return s.version
}

// ApplyConfig makes the node serve what the head asked for
func (s *Supervisor) ApplyConfig(ctx context.Context, cfg *fedpb.NodeConfig) ([]string, error) {
	s.adoptBuilds(cfg)
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureBinaries(); err != nil {
		return nil, err
	}
	if err := s.ensureKeys(); err != nil {
		return nil, err
	}
	rendered, err := xraycfg.Render(cfg, xraycfg.Keys{
		RealityPrivateKey: s.keys.PrivateKey,
		Mldsa65Seed:       s.keys.Mldsa65Seed,
	}, s.profiles)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(s.configPath(), rendered, 0o600); err != nil {
		return nil, err
	}
	if err := s.restartXray(); err != nil {
		return nil, err
	}
	// Порты открываем по факту применённого конфига: инбаунды тут те самые, что
	// уехали в ссылки, и хост с политикой DROP иначе съедает Xray так же тихо,
	// как съедал релей
	s.openConfiguredPorts(ctx, cfg)
	s.version = cfg.GetVersion()
	if err := saveAppliedVersion(s.appliedPath(), s.version); err != nil {
		log.Printf("supervisor: could not record applied config version: %v", err)
	}

	effective := make([]string, 0, len(cfg.GetInbounds()))
	for _, in := range cfg.GetInbounds() {
		effective = append(effective, in.GetTag())
	}
	return effective, nil
}

// adoptBuilds takes the build choice out of the config the head pushed.
//
// The flags stay as a fallback for a node started by hand, but the fleet's
// version is an operator decision: a donor should not have to log into their own
// server because the operator moved everyone onto a new Xray.
func (s *Supervisor) adoptBuilds(cfg *fedpb.NodeConfig) {
	if b := cfg.GetXrayBuild(); b.GetUrl() != "" {
		s.opts.XrayURL, s.opts.XraySHA512 = b.GetUrl(), b.GetSha512()
		s.wantXrayVersion = b.GetVersion()
	}
	if b := cfg.GetVktpBuild(); b.GetUrl() != "" {
		s.opts.RelayURL, s.opts.RelaySHA512 = b.GetUrl(), b.GetSha512()
	}
	s.autoUpgrade = cfg.GetAutoUpgrade()
}

// ensureBinaries downloads what is missing. Callers hold the lock
func (s *Supervisor) ensureBinaries() error {
	fetcher := binfetch.New(s.opts.BinDir)
	// Наличия бинаря мало: рядом должны лежать данные маршрутизации, без
	// которых Xray падает при загрузке конфига. Нода, обновлённая со старой
	// версии агента, имеет бинарь и не имеет их - и молча не поднимает ни один
	// инбаунд
	haveBinary := false
	if _, ok := fetcher.Installed("xray"); ok {
		haveBinary = true
		if fetcher.HasRoutingData() {
			return nil
		}
	}
	if s.opts.SkipDownload || s.opts.XrayURL == "" {
		if haveBinary {
			// Скачать неоткуда, но бинарь есть: пусть Xray сам решает, хватает
			// ли ему данных. Отказ здесь превратил бы рабочую ноду без geoip в
			// ноду, которая вообще не стартует
			return nil
		}
		return ErrNoBinary
	}
	if _, err := fetcher.Fetch(s.opts.XrayURL, "xray", s.opts.XraySHA512); err != nil {
		return err
	}
	if s.opts.RelayURL != "" {
		// A relay that fails to download must not stop the Xray half from
		// serving: half a node beats none
		_, _ = fetcher.Fetch(s.opts.RelayURL, "vk-turn-server", s.opts.RelaySHA512)
	}
	return nil
}

// ensureKeys mints the REALITY identity once and reuses it. Regenerating on
// every config push would hand every existing client a server that no longer
// matches the key they were given
func (s *Supervisor) ensureKeys() error {
	if s.keys.PrivateKey != "" {
		return nil
	}
	if loaded, err := loadKeys(s.keyPath()); err == nil && loaded.PrivateKey != "" {
		s.keys = loaded
		return nil
	}
	pair, err := realitykeys.Generate(s.xrayPath())
	if err != nil {
		return err
	}
	s.keys = pair
	if err := saveKeys(s.keyPath(), pair); err != nil {
		return err
	}
	return nil
}

// DrainAbuse samples the core if it is due and hands over what it saw.
//
// Driven by the heartbeat rather than a goroutine of its own: there is nothing
// to do between samples, and one fewer lifecycle to get wrong on somebody else's
// server is worth more than the tidiness of a loop
func (s *Supervisor) DrainAbuse() []*fedpb.AbuseSignal {
	s.mu.Lock()
	watcher, running := s.abuse, s.xray != nil && s.xray.Running()
	due := time.Since(s.lastAbuseSample) >= abusewatch.DefaultInterval
	if due {
		s.lastAbuseSample = time.Now()
	}
	s.mu.Unlock()

	if watcher == nil {
		return nil
	}
	if running && due {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		watcher.Sample(ctx)
		cancel()
	}
	return watcher.DrainAbuse()
}

// MeteredProfiles is what may be watched for abuse. Nothing else on the node is
// a federation profile, and watching the donor's own clients would be spying on
// somebody who never joined anything
func (s *Supervisor) MeteredProfiles() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.profiles))
	for _, p := range s.profiles {
		if p.Metered {
			out[p.Email] = p.ID
		}
	}
	return out
}

// PublicIdentity is what ConfigAck reports back. Only public halves leave
func (s *Supervisor) PublicIdentity() (publicKey, mldsa65Verify string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys.PublicKey, s.keys.Mldsa65Verify
}

func (s *Supervisor) restartXray() error {
	if s.xray != nil {
		_ = s.xray.Stop()
	}
	s.xrayCarry.Up += s.xrayLast.Up
	s.xrayCarry.Down += s.xrayLast.Down
	s.xrayLast = xrayapi.Counter{}
	s.probeCarry += s.probeLast
	s.probeLast = 0
	// The old connection points at a core that is gone
	_ = s.api.Close()
	s.xray = xrayproc.New(s.xrayPath(), s.configPath())
	if err := s.xray.Start(); err != nil {
		return err
	}
	s.watchDomains()
	return nil
}

// watchDomains держит подписку на ядро отдельной горутиной. Стрим рвётся вместе
// с ядром на каждом рестарте, поэтому переподключаемся сами, с паузой, чтобы не
// долбиться в ещё не поднявшийся Xray
func (s *Supervisor) watchDomains() {
	if s.domainsCancel != nil {
		s.domainsCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.domainsCancel = cancel
	watcher := s.domains
	api := s.api
	oldCoreLogged := false
	go func() {
		for ctx.Err() == nil {
			client, err := api.Watch()
			if err == nil {
				err = watcher.Run(ctx, client)
			}
			if ctx.Err() != nil {
				return
			}
			// Ядро без нашего сервиса - это старая сборка, а не поломка. Ждём
			// дольше и не срём в лог каждые пять секунд
			pause := 5 * time.Second
			if status.Code(err) == codes.Unimplemented {
				pause = 5 * time.Minute
				if !oldCoreLogged {
					oldCoreLogged = true
					log.Printf("domainwatch: core has no watch service, waiting for a build that has it")
				}
			} else {
				oldCoreLogged = false
				log.Printf("domainwatch: stream lost (%v), reconnecting", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(pause):
			}
		}
	}()
}

// DrainAddresses отдаёт отпечатки адресов, с которых работают профили
func (s *Supervisor) DrainAddresses() []*fedpb.ClientAddresses {
	s.mu.Lock()
	watcher := s.abuse
	s.mu.Unlock()
	if watcher == nil {
		return nil
	}
	return watcher.DrainAddresses()
}

// DrainDomains отдаёт накопленное окно наверх и забывает его
func (s *Supervisor) DrainDomains() *fedpb.DomainBatch {
	s.mu.Lock()
	watcher := s.domains
	s.mu.Unlock()
	if watcher == nil {
		return nil
	}
	batch := watcher.Drain()
	if addrs := s.DrainAddresses(); len(addrs) > 0 {
		if batch == nil {
			batch = &fedpb.DomainBatch{}
		}
		batch.Addresses = addrs
	}
	return batch
}

// ApplyProfiles adds and removes users on the live core.
//
// Rendering and restarting would drop every connection on the node, including
// the donor's own paying clients, so this goes over Xray's gRPC. The staged list
// is kept as well, because it is what the next config render writes out
func (s *Supervisor) ApplyProfiles(ctx context.Context, delta *fedpb.ProfileDelta) error {
	// Пиры VK TURN живут в релее, а не в ядре, и снятием профиля не убираются.
	// Делаем это первым: карантин обязан отрезать доступ, а не только перестать
	// выдавать новый
	s.dropPeers(ctx, delta.GetRemovePeerKeys())
	// У релея ограничителя скорости нет вовсе, поэтому режет ядро по адресу
	// пира: WireGuard терминируется прямо тут, и у каждого пира свой /32
	s.shapePeers(ctx, delta.GetPeerLimits())
	s.mu.Lock()
	drop := make(map[string]bool, len(delta.GetRemoveProfileIds()))
	for _, id := range delta.GetRemoveProfileIds() {
		drop[id] = true
	}
	if delta.GetReplace() {
		// The head is authoritative: anything not in this list was revoked while
		// the node was unreachable, and keeping it would serve somebody nobody is
		// accounting for
		keep := make(map[string]bool, len(delta.GetAdd()))
		for _, spec := range delta.GetAdd() {
			keep[spec.GetProfileId()] = true
		}
		for _, p := range s.profiles {
			if !keep[p.ID] {
				drop[p.ID] = true
			}
		}
	}

	var removed []xraycfg.Profile
	kept := s.profiles[:0]
	for _, p := range s.profiles {
		if drop[p.ID] {
			removed = append(removed, p)
			continue
		}
		kept = append(kept, p)
	}
	s.profiles = kept

	have := make(map[string]bool, len(s.profiles))
	for _, p := range s.profiles {
		have[p.ID+"\x00"+p.InboundTag] = true
	}
	var added []xraycfg.Profile
	for _, spec := range delta.GetAdd() {
		p := xraycfg.Profile{
			ID:         spec.GetProfileId(),
			UUID:       spec.GetUuid(),
			Email:      spec.GetEmail(),
			Flow:       spec.GetFlow(),
			InboundTag: spec.GetInboundTag(),
			Metered:    spec.GetMetered(),
			Level:      xraycfg.LevelFor(spec.GetUplinkBps(), spec.GetDownlinkBps()),
		}
		if have[p.ID+"\x00"+p.InboundTag] {
			// Already serving it. A replace pass re-sends everything, and adding
			// a user the core already has is an error rather than a no-op
			continue
		}
		if !p.Metered && p.Email != "" {
			if s.probeEmails == nil {
				s.probeEmails = map[string]struct{}{}
			}
			s.probeEmails[p.Email] = struct{}{}
		}
		s.profiles = append(s.profiles, p)
		added = append(added, p)
	}
	api, running := s.api, s.xray != nil && s.xray.Running()
	s.mu.Unlock()

	if !running {
		return nil
	}
	// Процесс уже поднят, а gRPC ядра слушает на секунду-другую позже, и первый
	// же ProfileDelta после рестарта иначе уходит в башку алармом
	if err := waitForAPI(ctx, api); err != nil {
		return err
	}
	var errs []error
	for _, p := range removed {
		if err := api.RemoveUser(ctx, p.InboundTag, p.Email); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range added {
		if err := api.AddUser(ctx, p.InboundTag, p.Email, p.UUID, p.Flow, p.Level); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// apiWait - сколько ждать gRPC ядра после запуска процесса
const apiWait = 15 * time.Second

func waitForAPI(ctx context.Context, api *xrayapi.Client) error {
	deadline := time.Now().Add(apiWait)
	for {
		if _, err := api.QueryTraffic(ctx, false); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// transportOf вытаскивает транспорт из тега инбаунда: fed-tcp это tcp
func transportOf(inboundTag string) string {
	return strings.TrimPrefix(inboundTag, "fed-")
}

// profileDeltasLocked считает, сколько каждый профиль пронёс с прошлого замера.
//
// Считаются только metered-профили, за остальные никто не отчитывается и
// расписок по ним нет нихуя
func (s *Supervisor) profileDeltasLocked(users map[string]xrayapi.Counter) []*fedpb.ProfileDeltaSample {
	if s.profileLast == nil {
		s.profileLast = map[string]xrayapi.Counter{}
	}
	now := time.Now().UnixMilli()
	out := make([]*fedpb.ProfileDeltaSample, 0, len(s.profiles))
	seen := make(map[string]struct{}, len(s.profiles))
	for _, p := range s.profiles {
		if !p.Metered {
			continue
		}
		// Ключ - учётка целиком, вместе с инбаундом: у профиля их несколько, и
		// по общему ключу дельты обоих транспортов затирали бы друг друга
		key := p.Email
		seen[key] = struct{}{}
		current := users[p.Email]
		previous := s.profileLast[key]
		s.profileLast[key] = current
		// Рестарт ядра обнуляет счётчики: тогда дельта - это само текущее
		// значение, а не отрицательная разница
		up, down := current.Up, current.Down
		if current.Up >= previous.Up && current.Down >= previous.Down {
			up, down = current.Up-previous.Up, current.Down-previous.Down
		}
		if up == 0 && down == 0 {
			continue
		}
		out = append(out, &fedpb.ProfileDeltaSample{
			ProfileId:      p.ID,
			UpDeltaBytes:   up,
			DownDeltaBytes: down,
			LastSeenMs:     now,
			Transport:      transportOf(p.InboundTag),
		})
	}
	for id := range s.profileLast {
		if _, ok := seen[id]; !ok {
			delete(s.profileLast, id)
		}
	}
	return out
}

// Sample reports cumulative counters.
//
// Xray traffic comes from the core's own stats rather than an access log, and
// the relay half from its control gRPC. Counters are never reset here: the head
// derives deltas, so a dropped sample is a gap and not lost traffic
func (s *Supervisor) Sample(ctx context.Context) (*fedpb.StatsSample, error) {
	s.mu.Lock()
	relay, api := s.relay, s.api
	running := s.xray != nil && s.xray.Running()
	s.mu.Unlock()

	sample := &fedpb.StatsSample{UnixMs: time.Now().UnixMilli()}
	if running {
		if traffic, err := api.QueryTraffic(ctx, false); err == nil {
			s.mu.Lock()
			// Замеры зондов идут через собственный профиль. В общую статистику
			// они входят, из бюджета донора вычитаются
			var probe uint64
			for email := range s.probeEmails {
				own := traffic.Users[email]
				probe += own.Up + own.Down
			}
			s.xrayLast = traffic.Total
			s.probeLast = probe
			probe += s.probeCarry
			up := s.xrayCarry.Up + traffic.Total.Up
			down := s.xrayCarry.Down + traffic.Total.Down
			perProfile := s.profileDeltasLocked(traffic.Users)
			s.mu.Unlock()
			sample.Profiles = perProfile
			sample.TotalUpBytes += up
			sample.TotalDownBytes += down
			sample.ProbeBytes += probe
		}
		// QueryStats lists everyone who ever passed a byte, so who is actually
		// connected has to come from the core's online list
		if online, err := api.OnlineUsers(ctx); err == nil {
			sample.ActiveSessions += uint32(len(online))
		}
	}
	if relay != nil {
		flow, err := relay.FlowStats(ctx)
		if err == nil {
			// Байты сокета в самоотчёт не идут: на публичный порт релея летит
			// весь мусор интернета - сканеры, боты, битые хендшейки, - и донору
			// это выставлялось бы как его трафик. Считаем по пирам, ниже
			sample.ActiveSessions += flow.ActiveSessions
			sample.ActiveStreams += flow.ActiveStreams
		}
		// Общий счётчик релея валит всех в одну кучу, и кто именно возит
		// трафик, видно только по пирам
		if peers, err := relay.Peers(ctx); err == nil {
			sample.Peers = s.peerDeltas(peers)
			// Расшифрованный трафик пиров - это и есть то, что нода реально
			// повезла для людей, и ровно за него подписывают расписки
			for _, peer := range peers {
				sample.TotalUpBytes += peer.RxBytes
				sample.TotalDownBytes += peer.TxBytes
			}
		}
	}
	return sample, nil
}

// Health reports what the node looks like right now
func (s *Supervisor) Health(ctx context.Context) (*fedpb.Heartbeat, error) {
	s.mu.Lock()
	xray, relay := s.xray, s.relay
	s.mu.Unlock()

	beat := &fedpb.Heartbeat{
		UnixMs:        time.Now().UnixMilli(),
		UptimeSeconds: uint64(time.Since(s.started).Seconds()),
		XrayState:     "stopped",
		VktpState:     "unknown",
	}
	if xray != nil && xray.Running() {
		beat.XrayState = "running"
	}
	beat.XrayVersion, beat.VktpVersion = s.ComponentVersions()
	beat.RelayEndpoint = s.relayEndpoint(ctx, relay)
	if relay != nil {
		st := relay.Status(ctx)
		beat.RelayFederation = st.Federation
		switch {
		case !st.Reachable:
			beat.VktpState = "unreachable"
		case st.Ready:
			beat.VktpState = "ready"
		default:
			// Answering but not serving is its own state: reporting it as
			// running would mark the node healthy while clients fail
			beat.VktpState = "starting"
		}
	}
	return beat, nil
}

// relayEndpoint склеивает внешний адрес ноды с портом релея: снаружи виден
// только адрес, а порт знает лишь сам релей
func (s *Supervisor) relayEndpoint(ctx context.Context, relay *vktpctl.Client) string {
	if relay == nil {
		return ""
	}
	st := relay.Status(ctx)
	if st.PublicIP == "" || st.ListenEndpoint == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(st.ListenEndpoint)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(st.PublicIP, port)
}

// SetRotationState reacts to the head parking or draining this node. Parking
// stops serving; draining keeps existing clients working and is therefore a
// scheduling decision, not a local one
func (s *Supervisor) SetRotationState(state fedpb.RotationState) error {
	s.mu.Lock()
	s.rotation = state
	xray, relay := s.xray, s.relay
	s.mu.Unlock()

	if state != fedpb.RotationState_ROTATION_STATE_PARKED {
		return nil
	}
	// Гасим ОБА пути. Останавливать только Xray бессмысленно: релей продолжал
	// возить трафик и жечь бюджет донора, которого башка уже вывела из ротации
	if relay != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := relay.Shutdown(ctx, "node parked by the head"); err != nil {
			log.Printf("supervisor: the relay did not stop while parking: %v", err)
		}
	}
	if xray != nil {
		return xray.Stop()
	}
	return nil
}

// peerDeltas считает, сколько каждый пир пронёс с прошлого замера.
//
// Рестарт релея обнуляет его счётчики, и дельта тогда - это само текущее
// значение, а не отрицательная разница
func (s *Supervisor) peerDeltas(peers []vktpctl.Peer) []*fedpb.PeerDeltaSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peerLast == nil {
		s.peerLast = map[string]vktpctl.Peer{}
	}
	out := make([]*fedpb.PeerDeltaSample, 0, len(peers))
	seen := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		seen[p.PublicKey] = struct{}{}
		previous := s.peerLast[p.PublicKey]
		s.peerLast[p.PublicKey] = p
		// Направление от лица человека, как и у Xray: RxBytes ядра это
		// принятое ОТ пира, то есть его аплоад. Перепутать значит сравнивать
		// с распиской вывернутые наизнанку цифры
		up, down := p.RxBytes, p.TxBytes
		if p.RxBytes >= previous.RxBytes && p.TxBytes >= previous.TxBytes {
			up, down = p.RxBytes-previous.RxBytes, p.TxBytes-previous.TxBytes
		}
		if up == 0 && down == 0 {
			continue
		}
		out = append(out, &fedpb.PeerDeltaSample{
			PublicKey: p.PublicKey, UpDeltaBytes: up, DownDeltaBytes: down,
		})
	}
	for key := range s.peerLast {
		if _, ok := seen[key]; !ok {
			delete(s.peerLast, key)
		}
	}
	return out
}

// shapePeers ставит потолки скорости пирам и запоминает, чей это адрес.
//
// Адрес нужен наблюдению: с wg-интерфейса видно только его, а имя человека
// знает башка, она пиров и выдавала
func (s *Supervisor) shapePeers(ctx context.Context, limits []*fedpb.PeerLimit) {
	if len(limits) == 0 {
		return
	}
	s.mu.Lock()
	if s.peerProfiles == nil {
		s.peerProfiles = map[string]string{}
	}
	for _, limit := range limits {
		if addr := hostOf(limit.GetAllowedIps()); addr != "" && limit.GetProfileId() != "" {
			s.peerProfiles[addr] = limit.GetProfileId()
		}
	}
	s.mu.Unlock()

	if s.shaper == nil {
		return
	}
	for _, limit := range limits {
		if err := s.shaper.Apply(ctx, limit.GetAllowedIps(), shaper.Limit{
			DownBps: limit.GetDownlinkBps(),
		}); err != nil {
			log.Printf("supervisor: the rate limit for %s did not apply: %v", limit.GetAllowedIps(), err)
		}
	}
}

// SetShaper включает ограничение скорости у пиров VK TURN
func (s *Supervisor) SetShaper(sh *shaper.Shaper) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shaper = sh
}

// ObserveRelaySighting принимает то, что наблюдатель снял с wg-интерфейса
func (s *Supervisor) ObserveRelaySighting(address, domain, ja3, ja4 string, at time.Time) {
	s.mu.Lock()
	profileID := s.peerProfiles[address]
	domains := s.domains
	s.mu.Unlock()
	if profileID == "" || domains == nil {
		// Про этот адрес башка лимита не присылала, значит вешать наблюдение
		// не на кого
		return
	}
	domains.ObserveRelay(profileID, domain, ja3, ja4, at)
}

// hostOf вытаскивает адрес из allowed_ips вида 10.8.0.5/32
func hostOf(allowedIPs string) string {
	first := strings.TrimSpace(strings.Split(allowedIPs, ",")[0])
	if idx := strings.Index(first, "/"); idx > 0 {
		first = first[:idx]
	}
	return first
}

// dropPeers выкидывает пиров VK TURN с релея
func (s *Supervisor) dropPeers(ctx context.Context, keys []string) {
	if len(keys) == 0 {
		return
	}
	s.mu.Lock()
	relay := s.relay
	s.mu.Unlock()
	if relay == nil {
		return
	}
	for _, key := range keys {
		if err := relay.DropPeer(ctx, key); err != nil {
			// Пира могло уже не быть: релей перезапускали, ключ отозвали раньше.
			// Это не повод бросать остальных
			log.Printf("supervisor: peer %s was not removed: %v", short(key), err)
		}
	}
}

// short режет ключ до узнаваемого куска: целиком он в журнале не нужен
func short(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12]
}

// ComponentVersions - что за сборки реально крутятся на ноде
func (s *Supervisor) ComponentVersions() (string, string) {
	s.mu.Lock()
	relay, xray := s.relay, s.xray
	want := s.wantXrayVersion
	s.mu.Unlock()

	xrayVersion := want
	if xray != nil && xray.Running() && xrayVersion == "" {
		xrayVersion = "running"
	}
	if relay == nil {
		return xrayVersion, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return xrayVersion, relay.Status(ctx).Version
}

// Country - страна ноды по её внешнему адресу. Голосуют локальная база и
// внешние справочники: у хостингов адреса переезжают между странами, и одна
// база регулярно отстаёт от жизни
func (s *Supervisor) Country(addr string) string {
	s.mu.Lock()
	resolver := s.country
	s.mu.Unlock()
	if resolver == nil || addr == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return resolver.Resolve(ctx, addr)
}

// RelayPublicIP - внешний адрес, который релей узнал у STUN. Пусто, когда релея
// нет или он ещё не спросил: адрес ноды тогда собирается только по интерфейсам
func (s *Supervisor) RelayPublicIP() string {
	s.mu.Lock()
	relay := s.relay
	s.mu.Unlock()
	if relay == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return relay.Status(ctx).PublicIP
}

// AttachRelay wires the relay control client once its address is known
func (s *Supervisor) AttachRelay(c *vktpctl.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.relay = c
}

// Stop shuts the children down
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.domainsCancel != nil {
		s.domainsCancel()
		s.domainsCancel = nil
	}
	_ = s.api.Close()
	if s.xray != nil {
		return s.xray.Stop()
	}
	return nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Upgrade acts on an operator's command: fetch a build and restart, or just
// restart what is already installed.
//
// Restarting Xray drops every live connection on this node, including the
// donor's own clients, so it happens only when somebody asked - never as a side
// effect of a config that merely mentions a version.
func (s *Supervisor) Upgrade(ctx context.Context, component, version, url, sha512 string, restartOnly bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch component {
	case "xray":
		if !restartOnly && url != "" {
			if _, err := binfetch.New(s.opts.BinDir).Fetch(url, "xray", sha512); err != nil {
				return err
			}
			s.opts.XrayURL, s.opts.XraySHA512, s.wantXrayVersion = url, sha512, version
		}
		return s.restartXray()
	case "vktp":
		if !restartOnly && url != "" {
			if _, err := binfetch.New(s.opts.BinDir).Fetch(url, "vk-turn-server", sha512); err != nil {
				return err
			}
			s.opts.RelayURL, s.opts.RelaySHA512 = url, sha512
		}
		// Релей не наш процесс: агент его качает, а запускает контейнер или
		// systemd рядом. Поэтому просим его перечитать себя сам и передаём
		// наверх то, что он сделать не смог, вместо того чтобы врать об успехе
		if s.relay == nil {
			return ErrNoRelay
		}
		applied, restart, err := s.relay.Reload(ctx)
		if err != nil {
			return err
		}
		if len(restart) > 0 {
			// То, что нельзя перечитать, применяется единственным честным
			// способом: релей выходит сам, а поднимает его тот, кто запускал
			reason := "restart required: " + strings.Join(restart, ", ")
			if err := s.relay.Shutdown(ctx, reason); err != nil {
				return fmt.Errorf("%w: %s", ErrRelayRestart, strings.Join(restart, ", "))
			}
			log.Printf("supervisor: relay asked to restart for %s", strings.Join(restart, ", "))
			return nil
		}
		log.Printf("supervisor: relay reloaded %s", strings.Join(applied, ", "))
		return nil
	default:
		return fmt.Errorf("supervisor: unknown component %q", component)
	}
}

// SetReceiptDoor включает приём расписок от клиентов из туннеля
func (s *Supervisor) SetReceiptDoor(door *receiptdoor.Door) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts = door
}

// DrainReceipts отдаёт то, что принесли клиенты. Нода тут курьер: подпись
// клиентская, и подделать её она не может
func (s *Supervisor) DrainReceipts() []*fedpb.TrafficReceipt {
	s.mu.Lock()
	door := s.receipts
	s.mu.Unlock()
	if door == nil {
		return nil
	}
	return door.Drain()
}

// relistenDrain - сколько прежний сокет релея доживает после переезда. У
// клиента в профиле ещё старый адрес, и он узнает новый только со следующей
// подпиской
const relistenDrain = 10 * time.Minute

// relayPortCheckInterval - как часто сверяем порт релея. Релей переживает нас:
// kubelet или systemd поднимут его заново на том, что записано в юните, и без
// повторной проверки нода тихо вернётся на общеизвестный порт
const relayPortCheckInterval = 30 * time.Second

// WatchRelayPort держит релей на порту этой ноды, сколько живёт агент.
//
// Разовой попытки мало: при старте пода агент успевает раньше, чем релей поднял
// свой gRPC, и первый заход упирается в connection refused
func (s *Supervisor) WatchRelayPort(ctx context.Context, fingerprint string) {
	ticker := time.NewTicker(relayPortCheckInterval)
	defer ticker.Stop()
	settled := ""
	for {
		endpoint, err := s.EnsureRelayPort(ctx, fingerprint)
		switch {
		case err != nil:
			log.Printf("supervisor: relay port not settled: %v", err)
		case endpoint != "" && endpoint != settled:
			log.Printf("supervisor: relay data plane on %s", endpoint)
			settled = endpoint
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// EnsureRelayPort сажает релей на порт этой ноды и открывает его на хосте.
//
// Порт выводится из отпечатка: он держится за машину, а не за запуск, поэтому
// переживает перезапуск и не совпадает у двух нод. Общеизвестное число тут
// хуже случайного - оно называет софт не хуже баннера, и одно правило у
// цензора гасит сразу весь флот
func (s *Supervisor) EnsureRelayPort(ctx context.Context, fingerprint string) (string, error) {
	s.mu.Lock()
	relay := s.relay
	s.mu.Unlock()
	if relay == nil {
		return "", nil
	}

	statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	current := relay.Status(statusCtx).ListenEndpoint

	// Порт, который релей уже держит, для выбора считается свободным: он занят
	// нами, и без этой поправки ответ уходит на один вперёд при каждом вызове
	var owned uint64
	if _, currentPort, splitErr := net.SplitHostPort(current); splitErr == nil {
		owned, _ = strconv.ParseUint(currentPort, 10, 32)
	}
	want, err := portpick.UDP(fingerprint, uint32(owned))
	if err != nil {
		return "", fmt.Errorf("no free udp port for the relay: %w", err)
	}
	target := net.JoinHostPort("0.0.0.0", strconv.FormatUint(uint64(want), 10))

	if uint32(owned) == want {
		// Уже там: остаётся убедиться, что хост его пускает
		return current, s.openRelayPort(ctx, want)
	}

	moveCtx, moveCancel := context.WithTimeout(ctx, 15*time.Second)
	defer moveCancel()
	moved, err := relay.Relisten(moveCtx, target, relistenDrain)
	if err != nil {
		return "", fmt.Errorf("relay refused to move to %s: %w", target, err)
	}
	log.Printf("supervisor: relay data plane moved from %s to %s", current, moved)
	return moved, s.openRelayPort(ctx, want)
}

// openConfiguredPorts пробивает в файрволе всё, что нода реально слушает.
//
// Донорская машина обычно приходит с включённым ufw и политикой DROP, и порт,
// которого там нет, выглядит как рабочая нода без единого клиента: инбаунд
// поднят, health зелёный, а снаружи не достучаться
func (s *Supervisor) openConfiguredPorts(ctx context.Context, cfg *fedpb.NodeConfig) {
	var rules []portgate.Rule
	for _, inbound := range cfg.GetInbounds() {
		// Публичный порт отличается от слушающего, когда инбаунд стоит за
		// прокси: снаружи стучатся именно в него
		for _, port := range []uint32{inbound.GetPort(), inbound.GetPublicPort()} {
			rules = append(rules, portgate.Rule{
				Port:  port,
				Proto: "tcp",
				What:  "xray " + inbound.GetTag(),
			})
		}
	}
	if vktp := cfg.GetVktp(); vktp.GetEnabled() {
		rules = append(rules,
			portgate.Rule{Port: vktp.GetListenPort(), Proto: "udp", What: "vk turn relay"},
			portgate.Rule{Port: vktp.GetWgListenPort(), Proto: "udp", What: "relay wireguard"},
		)
	}
	if len(rules) == 0 {
		return
	}
	err := portgate.OpenAll(ctx, rules)
	switch {
	case err == nil:
	case errors.Is(err, portgate.ErrNoTool):
		log.Printf("supervisor: no firewall tool here, assuming the inbound ports are already reachable")
	default:
		log.Printf("supervisor: could not open every inbound port: %v", err)
	}
}

// openRelayPort пробивает порт в файрволе хоста. Отсутствие инструмента - не
// повод валить ноду: на хосте без файрвола открывать нечего
func (s *Supervisor) openRelayPort(ctx context.Context, port uint32) error {
	err := portgate.OpenUDP(ctx, port)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, portgate.ErrNoTool):
		log.Printf("supervisor: no firewall tool here, assuming udp %d is already reachable", port)
		return nil
	default:
		return err
	}
}
