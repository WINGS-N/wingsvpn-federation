package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	fedpb "wingsnet.org/federation/gen/fedpb"
	headpb "wingsnet.org/federation/gen/headpb"
	intakepb "wingsnet.org/federation/gen/intakepb"
	provisioningpb "wingsnet.org/federation/gen/provisioningpb"
	"wingsnet.org/federation/internal/agent/binfetch"
	"wingsnet.org/federation/internal/common/tokenaead"
	"wingsnet.org/federation/internal/head/aggregator"
	"wingsnet.org/federation/internal/head/allocator"
	"wingsnet.org/federation/internal/head/assign"
	"wingsnet.org/federation/internal/head/chain"
	"wingsnet.org/federation/internal/head/destwatch"
	"wingsnet.org/federation/internal/head/devices"
	"wingsnet.org/federation/internal/head/domainfeed"
	"wingsnet.org/federation/internal/head/domainrules"
	"wingsnet.org/federation/internal/head/donations"
	"wingsnet.org/federation/internal/head/enforce"
	"wingsnet.org/federation/internal/head/epochs"
	"wingsnet.org/federation/internal/head/features"
	"wingsnet.org/federation/internal/head/fedserver"
	"wingsnet.org/federation/internal/head/fleet"
	"wingsnet.org/federation/internal/head/headserver"
	"wingsnet.org/federation/internal/head/intake"
	"wingsnet.org/federation/internal/head/kubeingress"
	"wingsnet.org/federation/internal/head/labeller"
	"wingsnet.org/federation/internal/head/leader"
	"wingsnet.org/federation/internal/head/nodetrust"
	"wingsnet.org/federation/internal/head/oracle"
	"wingsnet.org/federation/internal/head/payout"
	"wingsnet.org/federation/internal/head/pgstore"
	"wingsnet.org/federation/internal/head/probes"
	"wingsnet.org/federation/internal/head/provision"
	"wingsnet.org/federation/internal/head/rdap"
	"wingsnet.org/federation/internal/head/registry"
	"wingsnet.org/federation/internal/head/rotation"
	"wingsnet.org/federation/internal/head/stakes"
	"wingsnet.org/federation/internal/head/subs"
	"wingsnet.org/federation/internal/head/tokens"
	"wingsnet.org/federation/internal/head/upstream"
	"wingsnet.org/federation/internal/scan"
)

// shutdownGrace bounds how long a restart waits for open agent sessions
const shutdownGrace = 5 * time.Second

// silentQuiet - как долго после первого отказа молчим про то же устройство.
// Клиент повторяет запрос сразу же, и каждая попытка стоит ему 22 очка
const silentQuiet = 10 * time.Minute

func runHead(args []string) error {
	fs := newFlagSet("head")
	listen := fs.String("listen", "0.0.0.0:9310", "agent-facing gRPC listen address")
	advertise := fs.String("advertise", "", "endpoint nodes should dial after enrolling")
	fleetSecret := fs.String("fleet-secret", "", "secret keying the enroll transport, shared by all donors")
	mintFor := fs.String("mint", "", "mint an enroll token for this donor and print the install string")
	candidates := fs.String("reality-candidates", "", "comma-separated dest:port targets for agents to probe")
	realityDest := fs.String("reality-dest", "", "dest:port nodes borrow their tls identity from")
	// По умолчанию включено: трафик пишут сегодня, чтобы расшифровать завтра, и
	// подпись ML-DSA-65 нужна именно там. Помещается не в каждый заимствованный
	// хендшейк, поэтому снять можно - но это осознанное решение человека
	realityPQ := fs.Bool("reality-pq", true, "sign the borrowed certificate with ML-DSA-65; needs a dest whose handshake is large enough to hide it")
	realityAuto := fs.Bool("reality-auto", false, "pick the dest by scanning, and turn ML-DSA-65 on only if the winner verifiably carries it")
	realityPool := fs.String("reality-pool", "", "comma-separated candidates for -reality-auto; empty uses the built-in pool")
	scanBinDir := fs.String("scan-bin-dir", "/usr/local/wings/federation/bin", "where the xray used for scanning lives")
	tcpPort := fs.Uint("tcp-port", 443, "port for the reality tcp inbound")
	xhttpPort := fs.Uint("xhttp-port", 8443, "port for the reality xhttp inbound")
	statePath := fs.String("state", "/var/lib/wings/federation/registry.json", "where the node registry lives")
	panelListen := fs.String("panel-listen", "127.0.0.1:9311", "panel-facing gRPC listen address")
	panelSecret := fs.String("panel-secret", "", "secret keying the panel transport, never the fleet secret")
	subListen := fs.String("sub-listen", "127.0.0.1:9312", "subscription HTTP listen address")
	subBase := fs.String("sub-base", "", "public origin subscription URLs and the installer are served from")
	agentRelease := fs.String("agent-release", "", "where the agent binary lives, with __ARCH__ for the architecture")
	donationGB := fs.Uint("donation-gb", 0, "traffic the pasted install command declares, in GiB")
	allocPath := fs.String("allocations", "/var/lib/wings/federation/allocations.json", "where user allocations live")
	lifetimePath := fs.String("lifetime", "/var/lib/wings/federation/lifetime.json", "where the all-time byte counter lives")
	ingressRouteName := fs.String("ingress-route", "fed-node-reality", "name of the IngressRouteTCP the head keeps in step with the fleet")
	ingressService := fs.String("ingress-service", "fed-node-local", "service a matched connection is handed to")
	ingressPort := fs.Uint("ingress-port", 8443, "port that service listens on")
	dsn := fs.String("dsn", "", "postgres connection string; when set, the head keeps its state there instead of in files")
	provisionListen := fs.String("provision-listen", ":9313",
		"where the relays ask which client to mint a wg peer for; empty disables VK TURN")
	leaseName := fs.String("lease", "wingsv-fed-head", "name of the k8s lease that keeps one head active")
	requireProbe := fs.Bool("require-probe", false, "hand out only addresses a vantage point has confirmed")
	// Ноль означает, что выплаты не настроены и эпохи не закрываются вовсе:
	// считать деньги по случайно оставшейся в коде ставке нельзя
	payoutRate := fs.Uint64("payout-micro-per-gib", 0,
		"micro-USDT paid per GiB of traffic clients signed for; 0 disables accrual")
	payoutPeriod := fs.Duration("payout-period", epochs.DefaultPeriod, "how long one payout epoch lasts")
	chainRPC := fs.String("chain-rpc", "", "solana rpc endpoint for publishing epochs (empty keeps epochs off-chain)")
	chainProgram := fs.String("chain-program", "", "base58 address of the payouts program")
	chainKey := fs.String("chain-key", "", "path to the solana keypair that publishes epochs")
	chainTreasury := fs.String("chain-treasury", "", "token account the payouts are made from")
	chainMint := fs.String("chain-mint", "", "mint of the payout token, donors get an account for it")
	stakeRequired := fs.Uint64("stake-required-micro", 20_000_000,
		"how much a donor must post as a stake before any payout accrues to them")
	payoutFloor := fs.Uint64("payout-floor-micro-per-gib", 0,
		"below this the epoch pays nothing: dust costs more to hand out than it is worth")
	payoutShare := fs.Uint("payout-treasury-share", 60,
		"percent of the treasury one epoch may spend, the rest stays as reserve")
	// Ключ читается из окружения, а не из флага: флаг видно в списке процессов
	// любому, кто имеет шелл на машине
	labelModel := fs.String("label-model", labeller.DefaultModel, "which model labels the feature snapshots")
	// Зонд ходит своим секретом и на своём порту. Причина простая: до башки он
	// добирается через ноды, а нода со флотским секретом читала бы и правила бы
	// его отчёты как хотела. Со своим ключом она видит непрозрачные байты
	probeListen := fs.String("probe-listen", "", "listen address for vantage points; empty puts them on the agent port")
	probeSecret := fs.String("probe-secret", "", "secret keying the vantage point transport; empty reuses the fleet secret")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	// Postgres when a dsn is given, files otherwise. The files are not dead
	// weight: a donated single-host deployment has no database, and the oracle's
	// feature store is the only part that truly needs one
	var (
		db           *pgstore.DB
		regStore     registry.Store           = registry.NewFileStore(*statePath)
		allocStore   allocator.Store          = allocator.NewFileStore(*allocPath)
		lifetimeSink aggregator.LifetimeStore = aggregator.NewLifetimeFile(*lifetimePath)
	)
	if *dsn != "" {
		opened, err := pgstore.Open(*dsn)
		if err != nil {
			return err
		}
		db = opened
		defer db.Close()
		regStore = registry.NewPGStore(db.Gorm())
		allocStore = allocator.NewPGStore(db.Gorm())
		lifetimeSink = aggregator.NewLifetimePG(db.Gorm())

		// One-way, and only into empty tables, so a redeploy onto Postgres
		// carries the fleet across instead of losing it
		if err := pgstore.SeedFromFiles(context.Background(),
			pgstore.Seeder{
				Name:  "nodes",
				Empty: db.TableEmpty(&pgstore.Node{}),
				Copy: func() (bool, error) {
					nodes, err := registry.NewFileStore(*statePath).Load()
					if err != nil || len(nodes) == 0 {
						return false, err
					}
					return true, regStore.Save(nodes)
				},
			},
			pgstore.Seeder{
				Name:  "allocations",
				Empty: db.TableEmpty(&pgstore.Allocation{}),
				Copy: func() (bool, error) {
					state, err := allocator.NewFileStore(*allocPath).Load()
					if err != nil || len(state) == 0 {
						return false, err
					}
					return true, allocStore.Save(state)
				},
			},
			pgstore.Seeder{
				Name:  "counters",
				Empty: db.TableEmpty(&pgstore.Counter{}),
				Copy: func() (bool, error) {
					stored, err := aggregator.NewLifetimeFile(*lifetimePath).Load()
					if err != nil || stored == 0 {
						return false, err
					}
					return true, lifetimeSink.Save(stored)
				},
			},
		); err != nil {
			return err
		}
	}

	reg, err := registry.Open(regStore)
	if err != nil {
		return err
	}
	store := tokens.New()
	if db != nil {
		// Токен зачисления переживает выкат башки только в базе
		store.SetBackend(pgstore.NewTokenStore(db.Gorm()))
	}

	// Minting keeps the head running: the token store is in memory, so a process
	// that minted and exited would take the token with it
	if *mintFor != "" {
		token, err := store.Mint(*mintFor, 24*time.Hour)
		if err != nil {
			return err
		}
		log.Printf("enroll string for %s: %s", *mintFor, tokens.JoinCompound(*fleetSecret, token))
	}

	endpoint := *advertise
	if strings.TrimSpace(endpoint) == "" {
		endpoint = *listen
	}
	srv := fedserver.New(reg, store, endpoint)

	// Флаги теперь только начальное значение: дальше флотом рулит оператор из
	// панели, и его выбор лежит в базе, а не в аргументах пода
	var fleetStore fleet.Store
	if db != nil {
		fleetStore = pgstore.NewFleetStore(db.Gorm())
	}
	fleetMgr, err := fleet.New(fleetStore, fleet.Settings{
		RealityDest: *realityDest,
		AutoDest:    *realityAuto,
		PostQuantum: *realityPQ,
		TCPPort:     uint32(*tcpPort),
		XHTTPPort:   uint32(*xhttpPort),
	})
	if err != nil {
		return err
	}
	srv.SetFleet(fleetMgr)

	current := fleetMgr.Settings()
	dest, postQuantum := current.RealityDest, current.PostQuantum
	if current.AutoDest && dest == "" {
		chosen, pq, err := pickDest(*realityPool, *scanBinDir)
		if err != nil {
			return err
		}
		dest, postQuantum = chosen, pq
		current.RealityDest, current.PostQuantum = dest, pq
		if _, err := fleetMgr.Update(current); err != nil {
			return err
		}
	}
	if dest != "" {
		srv.SetNodeConfig(current.Apply(
			defaultNodeConfig(dest, current.TCPPort, current.XHTTPPort, postQuantum)))
	}
	if *candidates != "" {
		srv.SetRealityCandidates(strings.Split(*candidates, ","))
	}

	// Users, nodes and the rotation loop. The allocator is the only place a user
	// and a node meet, which is what keeps the donor-facing side unable to join
	// the two even by accident
	// Requiring proof is deliberately an operator decision rather than something
	// the head switches on the moment a probe appears: flipping it automatically
	// means one dying vantage point silently parks the whole fleet
	scoring := assign.DefaultOptions()
	scoring.RequireProbe = *requireProbe
	alloc, allocErr := allocator.Open(reg, srv, srv.ConfigFor, scoring, allocStore)
	if allocErr != nil {
		return allocErr
	}
	// Vantage points measure through a profile of their own, and the reconcile
	// has to know about it or a reconnecting node would delete the credential the
	// measurements run through
	probeFleet := probes.New(reg, srv, srv.ConfigFor)
	srv.SetProbeFleet(probeFleet.Targets, probeFleet.Ingest)

	// The oracle scores, the enforcer acts, and the allocator obeys. Kept as
	// three pieces because a wrong score is an opinion while a wrong revocation
	// is a user with no internet
	judge := oracle.NewJudge(oracle.NewRulesScorer())
	if db != nil {
		judge.SetSink(pgstore.NewOracleStore(db.Gorm()))
		if err := judge.Restore(time.Now().Add(-oracle.RetainWindow)); err != nil {
			log.Printf("head: oracle history unreadable: %v", err)
		}
	}
	enforcer := enforce.New(judge, alloc, alloc.UserForProfile)
	// Квота без применения - это просто цифра на экране. Исчерпал - едешь на
	// полу скорости, но связь остаётся
	enforcer.SetUsage(alloc)
	srv.SetAbuseSink(enforcer.Observe)
	var domainStore *pgstore.DomainStore
	// Доверие к нодам живёт отдельно от людского: шкала другая и последствия
	// другие, а врать о трафике ноде выгоднее всех
	nodeJudge := nodetrust.NewJudge()
	// Нода обязана стучать, куда ходят её клиенты: ослепшая нода это либо старый
	// агент, либо донор, спрятавший ферму
	watchAudit := nodetrust.NewWatchAudit(nodeJudge)
	watchAudit.SetLogger(log.Printf)
	srv.SetRelayModeSink(watchAudit.ObserveRelayMode)
	// Клиент говорит свой адрес сам, ноды присылают отпечатки того, что видят
	var addressBook *intake.AddressBook
	// Домены пишутся сырьём и живут ограниченный срок. На одних классах никакую
	// модель не обучишь, а скам с кардингом по классу вообще не отличить
	if db != nil {
		domains := pgstore.NewDomainStore(db.Gorm(), alloc.UserForProfile)
		srv.SetDomainSink(func(batch *fedpb.DomainBatch, nodeID string) {
			watchAudit.ObserveDomains(nodeID)
			if addressBook != nil {
				addressBook.Record(batch)
			}
			if err := domains.Record(batch, nodeID); err != nil {
				log.Printf("head: observations from node %s not stored: %v", nodeID, err)
			}
		})
		domainStore = domains
	}
	alloc.SetBandFor(func(userID string) int { return enforcer.Band(userID).NodesFor() })
	srv.SetUsage(alloc)
	alloc.SetSpeedFor(enforcer.Speed)
	srv.SetProfileSource(func(nodeID string) []*fedpb.ProfileSpec {
		return append(alloc.SpecsFor(nodeID), probeFleet.SpecsFor(nodeID)...)
	})
	// Одна активная башка: обе реплики держали бы стримы разных агентов и
	// разошлись бы в цифрах. Резерв не проходит readiness, поэтому Service его
	// не выбирает
	var (
		kube    *kubeingress.Client
		elector *leader.Elector
	)
	if kubeingress.Available() {
		if kc, kerr := kubeingress.New(); kerr != nil {
			log.Printf("head: kube api unavailable: %v", kerr)
		} else {
			kube = kc
			elector = leader.New(kc, *leaseName, podIdentity())
			// Service ходит по метке: активная башка ставит её себе, резерв
			// снимает
			elector.OnChange(func(leading bool) {
				value := any(nil)
				if leading {
					value = "active"
				}
				path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", kc.Namespace(), podIdentity())
				patch := map[string]any{"metadata": map[string]any{
					"labels": map[string]any{"wingsv.role": value},
				}}
				if err := kc.PatchRaw(context.Background(), path, patch); err != nil {
					log.Printf("head: could not mark this pod: %v", err)
				}
			})
		}
	}

	// Провижн VK TURN: релей на ноде спрашивает башку, кому минтить пир.
	// Ходит он с тем же токеном, что и его управляющий API, поэтому здесь
	// обычный Bearer, а не tokenaead
	alloc.SetProvisionSecret(*fleetSecret)
	var receipts *pgstore.ReceiptStore
	if db != nil {
		receipts = pgstore.NewReceiptStore(db.Gorm())
	}
	var vkPeers provision.Peers
	if receipts != nil {
		vkPeers = receipts
		// Карантин обязан снимать и пира релея: учётка ядра без этого отрезана,
		// а туннель VK TURN продолжает работать по уже выданному ключу
		alloc.SetPeers(receipts)
		// Трафик VK TURN приходит по ключу пира: без этой связки он ложился
		// только в бюджет донора, а расход человека оставался нулевым
		srv.SetPeerOwners(receipts)
	}
	provisionServer, provisionErr := startProvisioning(*provisionListen, *fleetSecret, alloc, vkPeers, fleetLinks{fleetMgr})
	if provisionErr != nil {
		return provisionErr
	}

	// Подписка без второй проверки - предъявительский ключ: переслал ссылку, и
	// человек подключился. Слоты закрепляют её за устройствами аккаунта
	var deviceGate subs.Devices
	var onSilentClient func(string)
	if db != nil {
		deviceGate = devices.New(pgstore.NewDeviceStore(db.Gorm()), bandDevices{enforcer})
		// Клиент, которому ответили 403, ломится ещё и ещё - это одна попытка
		// подключиться, а не пять нарушений. Без склейки человек уезжал в
		// карантин за полминуты, ни разу не подключившись
		silentSeen := map[string]time.Time{}
		var silentMu sync.Mutex
		onSilentClient = func(subjectID string) {
			now := time.Now()
			silentMu.Lock()
			last, seen := silentSeen[subjectID]
			if seen && now.Sub(last) < silentQuiet {
				silentMu.Unlock()
				return
			}
			silentSeen[subjectID] = now
			silentMu.Unlock()
			enforcer.ObserveSubject(&fedpb.AbuseSignal{
				ProfileId: subjectID,
				Kind:      fedpb.AbuseKind_ABUSE_KIND_NO_DEVICE_ID,
				Count:     1,
			}, "")
		}
	}
	// Настройки пути VK TURN оператор правит в панели: в инфраструктуре звонков
	// что-то меняется, и чинить это выкаткой новой версии приложения значит
	// оставить людей без связи, пока все обновятся
	turnPath := func() subs.TurnSettings {
		set := fleetMgr.Settings()
		return subs.TurnSettings{
			BrowserFingerprint: set.VKFingerprint,
			WrapMode:           set.VKWrapMode,
			WrapCipher:         set.VKWrapCipher,
			DNSMode:            set.VKDNSMode,
			VKAuthMode:         set.VKAuthMode,
			VKLinks:            set.VKLinks,
		}
	}
	// Потолок трафика съебывает в заголовок подписки: приложение рисует остаток
	// само, и человек видит лимит ДО того, как в него ебанётся
	quota := func(subjectID string) uint64 { return oracle.QuotaFor(judge.Judge(subjectID).Confidence) }
	subServer, subErr := startSubscriptions(*subListen, alloc, endpoint, *agentRelease, deviceGate, onSilentClient, turnPath, quota)
	if subErr != nil {
		return subErr
	}

	// The panel gets its own listener and its own secret. Reusing the fleet
	// secret would hand every donated node the operator's view of the federation
	// Помесячная история: счётчик за период обнуляется, и без неё донору нечего
	// показать за прошлый месяц
	var donationStore donations.Store = donations.NewMemStore()
	if db != nil {
		donationStore = donations.NewPGStore(db.Gorm())
	}
	ledger := donations.New(donationStore)
	srv.Aggregator().OnDelta(ledger.Add)

	panelSrv := headserver.New(reg, srv.Aggregator(), store, *fleetSecret)
	panelSrv.SetDonations(ledger)
	panelSrv.SetVantages(srv)
	if domainStore != nil {
		panelSrv.SetDomainHistory(domainHistory{domainStore})
	}
	panelSrv.SetOracle(judge)
	panelSrv.SetNodeTrust(nodeJudge)
	// Панель управляет флотом через башку, а не через values чарта
	panelSrv.SetFleet(fleetMgr, srv)
	base := subscriptionBase(*subBase, *subListen)
	panelSrv.SetAllocator(alloc, base)
	panelSrv.SetInstaller(base, uint32(*donationGB))
	// Расписки это единственная цифра о трафике, которой можно верить: свои
	// счётчики нода рисует сама, и платить по ним значит платить за воздух
	var intakeSrv *intake.Server
	var receiptReconciler *intake.Reconciler
	if receipts != nil {
		intakeSrv = intake.New(receipts, receipts)
		// Расходятся - значит поверх нашего туннеля крутится ещё один или
		// профилем пользуется не он
		// Расписка проверяется по журналу выдачи башки, а не по цифрам ноды:
		// агент у донора свой, и молчащая нода иначе отбивала бы клиентам подписи
		intakeSrv.SetGrants(alloc.HeldNode, reg.NodeByAddress)
		// Расписка, доехавшая из очереди с опозданием, закрывает окно, за
		// молчание в котором человека уже наказали: снимаем обвинение тем же
		// фактом, который его опроверг
		intakeSrv.SetAmnesty(func(subjectID string, from, to time.Time) int {
			return judge.Forgive(subjectID, fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS, from, to)
		})
		// Расписки, которые клиент не смог довезти сам и отдал ноде. Проверки те
		// же: курьер не выигрывает ничего от того, что нёс чужое
		srv.SetReceiptSink(func(receipts []*fedpb.TrafficReceipt) {
			intakeSrv.AcceptCarried(receipts)
		})
		addressBook = intake.NewAddressBook(alloc.UserForProfile)
		intakeSrv.SetSeen(addressBook)
		intakeSrv.SetAddressSink(func(subjectID, claimed string) {
			enforcer.ObserveSubject(&fedpb.AbuseSignal{
				ProfileId: subjectID,
				Kind:      fedpb.AbuseKind_ABUSE_KIND_ADDRESS_MISMATCH,
				Count:     1,
			}, "")
			log.Printf("intake: %s claims %s, no node has seen it", subjectID, claimed)
		})
		// Сверка идёт в обе стороны: нода говорит, сколько провезла, клиент
		// подписывает, сколько получил. Молчание клиента при живом трафике это
		// либо чужой клиент, либо кому-то есть что прятать
		receiptReconciler = intake.NewReconciler(alloc, receipts, enforcer.ObserveSubject, log.Printf)
	}
	panelServer, panelErr := startPanelServer(*panelListen, *panelSecret, panelSrv, intakeSrv)
	if panelErr != nil {
		return panelErr
	}

	// One listener keyed by the fleet secret. The per-donor token authorises
	// inside that stream, where a passive observer cannot read it
	// Пинги от агентов и зондов принимаются даже без активных стримов, а сама
	// башка простукивает молчащие соединения: иначе переезд пода оставляет
	// стрим "живым" с обеих сторон, не передавая ничего
	grpcServer := grpc.NewServer(
		grpc.Creds(tokenaead.Server(*fleetSecret)),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	fedpb.RegisterFederationServer(grpcServer, srv)

	ln, lnErr := net.Listen("tcp", *listen)
	if lnErr != nil {
		return lnErr
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The public total has to survive a deploy: a counter that restarts at zero
	// tells visitors the donors have carried less than they have
	if stored, err := lifetimeSink.Load(); err != nil {
		log.Printf("head: lifetime counter unreadable, starting from the live total: %v", err)
	} else {
		srv.Aggregator().LoadLifetime(stored)
	}
	if period, ok := lifetimeSink.(aggregator.PeriodStore); ok {
		if base, err := period.LoadPeriodBase(); err == nil {
			srv.Aggregator().LoadPeriodBase(base)
		}
	}
	if receiptReconciler != nil {
		go leader.WhileLeading(ctx, elector, receiptReconciler.Run)
	}
	// Судить надо обе стороны. Нода тоже умеет пиздеть: завысить трафик ради
	// выплаты, светить зелёным здоровьем и не везти при этом нихуя
	if receipts != nil {
		auditor := nodetrust.NewAuditor(srv.Aggregator(), receipts, reg, nodeJudge, log.Printf)
		// Платим строго за байты, а значит появляется смысл гонять трафик через
		// себя же: нода, весь объём которой висит на паре подписей, это ровно
		// та картина
		auditor.WatchClientMix(receipts)
		// Дерево приглашений приезжает от панели: точная проверка возможна
		// только с ним, без него остаётся грубая, по концентрации
		tree := nodetrust.NewTree()
		auditor.WatchInviteTree(tree, nodeDonors{reg})
		panelSrv.SetInviteTree(tree)
		go leader.WhileLeading(ctx, elector, auditor.Run)
	}
	go leader.WhileLeading(ctx, elector, func(ctx context.Context) {
		tick := time.NewTicker(nodetrust.WatchSweepEvery)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				totals, err := srv.Aggregator().NodeTraffic(time.Now())
				if err != nil {
					continue
				}
				watchAudit.Sweep(totals)
			}
		}
	})
	// Купленные подписки: заводит их владелец, и по умолчанию всё это выключено.
	// За чужим сервером наш Oracle слеп, поэтому решение раздавать принимает
	// человек, а не код по факту своего наличия
	if db != nil {
		pool := upstream.NewPool(pgstore.NewUpstreamStore(db.Gorm()), log.Printf)
		if err := pool.Load(); err != nil {
			log.Printf("head: bought subscriptions unreadable: %v", err)
		}
		// Прикроют адрес башки - пойдём за телом через ноды: у них адреса свои
		pool.SetRelay(srv)
		assigner := upstream.NewAssigner(pool)
		assigner.SetTrust(upstream.TrustAbove(upstream.MinConfidence, upstreamVerdicts{judge}))
		panelSrv.SetUpstreams(pool)
		alloc.SetUpstreams(assigner)
		go leader.WhileLeading(ctx, elector, pool.Run)
	}
	// Заносы деньгами греют доверие, и хранить их надо там же, где всё денежное
	if db != nil {
		donations := pgstore.NewEpochStore(db.Gorm())
		panelSrv.SetMoneyDonations(judge, donations)
		// Поднимаем оплаченное: без этого выкат башки стирает всё, за что люди
		// уже заплатили
		if rows, err := donations.Donations(time.Now().Add(-oracle.RetainWindow)); err != nil {
			log.Printf("head: donations unreadable: %v", err)
		} else if len(rows) > 0 {
			credits := make([]oracle.Credit, 0, len(rows))
			for _, row := range rows {
				credits = append(credits, oracle.Credit{
					SubjectID: row.SubjectID, AmountMicro: uint64(row.AmountMicro), At: row.At,
				})
			}
			judge.LoadCredits(credits)
			log.Printf("head: restored %d donations", len(credits))
		}
	}
	// Деньги считаются только там, где есть база: эпоху надо пережить рестарт,
	// а файлам такое не доверяют
	if db != nil && *payoutRate > 0 {
		store := epochStore{pgstore.NewEpochStore(db.Gorm())}
		collector := epochs.NewCollector(
			payoutFleet{reg}, srv.Aggregator(), receipts, trustFactor{nodeJudge},
			payoutAddresses(store), store,
			payout.Rate{MicroPerGiB: payout.Micro(*payoutRate)}, log.Printf,
		)
		loop := epochs.NewLoop(collector, store.store, *payoutPeriod, log.Printf)
		// Публикация включается только когда названы все трое: без цепочки эпохи
		// просто копятся в базе, и это законный режим
		if *chainRPC != "" && *chainProgram != "" && *chainKey != "" {
			publisher, err := newChainPublisher(*chainRPC, *chainProgram, *chainKey)
			switch {
			case err != nil:
				log.Printf("head: chain publishing is off: %v", err)
			case *chainTreasury == "" || *chainMint == "":
				log.Printf("head: chain publishing is off: -chain-treasury and -chain-mint are required")
			default:
				publisher.SetTreasury(chain.MustKey(*chainTreasury))
				// Счета доноров держит база: кошелёк токенов не хранит, деньги
				// идут на его токен-аккаунт, и заводится он один раз
				publisher.SetTokens(func(wallet string) (chain.Pubkey, bool) {
					accounts, err := store.store.TokenAccounts()
					if err != nil {
						log.Printf("head: donor token accounts are unreadable: %v", err)
						return chain.Pubkey{}, false
					}
					account, ok := accounts[wallet]
					if !ok {
						return chain.Pubkey{}, false
					}
					return chain.MustKey(account), true
				})
				loop.SetPublisher(publisher, store.store)
				loop.SetPending(store)
				// Цена плавает по казне и объявляется на период вперёд. Наша
				// нынешняя ставка тут потолок: выше не платим даже с набитой
				// казной, иначе раздадим всё за одну эпоху
				loop.SetRates(
					epochRates(store),
					chainTreasuryBalance{publisher.Client(), chain.MustKey(*chainTreasury)},
					payout.RateBounds{
						Cap:      payout.Micro(*payoutRate),
						Floor:    payout.Micro(*payoutFloor),
						SharePct: uint32(*payoutShare),
					},
				)
				// Состоявшиеся выплаты кладём в базу: без ссылки на транзакцию
				// донор видит цифру, а не деньги
				publisher.SetPaidSink(func(number uint64, wallet string, micro uint64, tx string) {
					donor, ok, err := store.store.DonorByAddress(wallet)
					if err != nil || !ok {
						log.Printf("head: payout %s left out of the statement: the wallet belongs to nobody", wallet)
						return
					}
					if err := store.store.MarkPaid(pgstore.PayoutTxRow{
						Number: number, DonorID: donor, Address: wallet,
						Micro: int64(micro), TxRef: tx, PaidAt: time.Now().UTC(),
					}); err != nil {
						log.Printf("head: payout %s was not recorded: %v", tx, err)
					}
				})
				// Донор называет кошелёк - счёт под токен заводит башка. Это
				// стоит ренты и одной транзакции, зато человеку не надо ничего
				// знать про токен-аккаунты
				mint := chain.MustKey(*chainMint)
				panelSrv.SetTokenOpener(func(donorID, wallet string) error {
					account, _, err := publisher.Client().OpenAccount(
						ctx, publisher.Signer(), mint, chain.MustKey(wallet),
					)
					if err != nil {
						return err
					}
					return store.store.SetTokenAccount(donorID, chain.Base58(account))
				})
				// Залог: без него донор возит трафик даром. Деньги приходят
				// на его личный счёт откуда угодно, а в хранилище их проносим
				// мы - подписать перевод с биржи некому
				guard := stakes.New(
					publisher, payoutAddresses(store), mint, *stakeRequired, log.Printf,
				)
				collector.SetStaked(guard)
				panelSrv.SetStakes(guard)
				go guard.Run(ctx, stakeSweepEvery)
				log.Printf("head: a donor is paid once they stake %d micro-USDT", *stakeRequired)
				// Заносы юзеров приходят обычным переводом на приёмный счёт
				// башки и до казны сами не доходят. Проносим их через
				// программу: там с них снимается доля оператора, остальное
				// падает донорам
				go sweepDonations(ctx, publisher, mint)
				log.Printf("head: epochs go to %s and pay out of %s", *chainRPC, *chainTreasury)
			}
		}
		go leader.WhileLeading(ctx, elector, loop.Run)
		panelSrv.SetPayouts(headPayouts(store))
		panelSrv.SetPendingAccruals(pendingAccruals{collector: collector, loop: loop})
		log.Printf("head: accruing %d micro-USDT per GiB over %s epochs", *payoutRate, *payoutPeriod)
	}
	if domainStore != nil {
		go domainStore.RunSweeper(ctx, log.Printf)
		// Разбор доменов - такой же источник обвинений, как сигналы с ноды. На
		// одних счётчиках мошенничество от обычной жизни не отличить
		rules := domainrules.NewLoop(freshSightings{domainStore}, enforcer.ObserveSubject, log.Printf)
		// Векторы копятся с первого дня: свёрнутый в вердикт вектор проёбан
		// навсегда, а без него учить модель будет не на чем
		ml := pgstore.NewMLStore(db.Gorm())
		rules.SetRecorder(ml)
		// Разметку показываем человеку: учить бустинг на непроверенной машинной
		// метке значит выучить её ошибки и потом резать по ним живых людей
		panelSrv.SetLabels(labelStore{ml})
		// Возраст домена спрашиваем у реестра и кешируем: домен стареет медленно,
		// а лимиты у реестров злые
		rules.SetAges(rdap.NewResolver(rdap.New(), pgstore.NewRDAPStore(db.Gorm()), log.Printf))
		// Чужие списки ложатся рядом со своими правилами: список знает уже
		// спалившееся, а форма поведения ловит то, чего в списках ещё нет
		feeds := domainfeed.NewPool(pgstore.NewFeedStore(db.Gorm()), log.Printf)
		feeds.Restore()
		rules.SetFeed(feeds)
		go leader.WhileLeading(ctx, elector, feeds.Run)
		// Разметка: без меток бустинг мёртв, а руками десятки тысяч снимков не
		// разметит никто. Нет ключа - разметчик просто не заводится
		if key := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); key != "" {
			marker := labeller.NewLoop(labeller.NewClient(key, *labelModel), ml, features.Version, log.Printf)
			// Обвинение по числам перепроверяется по доменам: половина
			// подозрительных цифр объясняется одним взглядом на то, куда человек
			// ходил. Наружу они едут ТОЛЬКО по обвинениям
			marker.SetDomains(reviewDomains{domainStore}, features.DailyWindow)
			go leader.WhileLeading(ctx, elector, marker.Run)
			log.Printf("head: snapshots are labelled by %s", *labelModel)
		}
		if model, shadow, err := ml.ActiveModel(); err != nil {
			log.Printf("head: stored model unreadable: %v", err)
		} else if model != nil {
			rules.SetModel(domainrules.NewModelScorer(model), shadow)
			log.Printf("head: model %s loaded, trained on %d rows, shadow=%v",
				model.Version(), model.TrainedOn(), shadow)
		}
		go leader.WhileLeading(ctx, elector, rules.Run)
		// Суточный ритм разбирается своим кругом: в десятиминутном окне суток
		// не видно, а ровная полка круглые сутки видна только на неделе
		daily := domainrules.NewDailyLoop(freshSightings{domainStore}, enforcer.ObserveSubject, log.Printf)
		go leader.WhileLeading(ctx, elector, daily.Run)
	}
	go srv.Aggregator().PersistTo(ctx.Done(), lifetimeSink, time.Minute)
	// Сессия агента висит на одной реплике, поэтому в памяти у каждой только
	// её ноды. Общий срез в базе даёт обеим одинаковую картину, и цифры не
	// прыгают от того, кому достался запрос
	if db != nil {
		shared := sharedNodes{pgstore.NewNodeTrafficStore(db.Gorm())}
		if err := srv.Aggregator().RestoreNodes(shared); err != nil {
			log.Printf("head: node counters unreadable, starting from zero: %v", err)
		}
		go srv.Aggregator().SyncSharedAndLifetime(ctx.Done(), shared, lifetimeSink, 5*time.Second)
	}
	go ledger.Run(ctx.Done(), time.Minute)

	// Автовыбор dest - это не разовая настройка при старте. Заимствованный хост
	// перестаёт отвечать, теряет сертификат или становится недоступен оттуда, где
	// сидят люди, и тогда весь флот держит инбаунды, падающие на хендшейке, при
	// этом рапортуя о здоровье
	// Запускаем всегда: сам watcher на каждой проверке смотрит, включён ли
	// автовыбор. Условие здесь означало бы, что тумблер в панели начинает
	// работать только после перезапуска башки
	{
		watcher := destwatch.New(destwatch.Options{
			Fleet: fleetMgr,
			Probe: func(ctx context.Context) ([]*scan.Result, error) {
				return scanPool(ctx, *realityPool), nil
			},
			Notify: func() {
				s := fleetMgr.Settings()
				srv.SetNodeConfig(s.Apply(
					defaultNodeConfig(s.RealityDest, s.TCPPort, s.XHTTPPort, s.PostQuantum)))
			},
		})
		go leader.WhileLeading(ctx, elector, watcher.Run)

		// Башка из своей сети видит дохлый dest здоровым: разваливается связка
		// dest с подписью, а это заметно только оттуда, откуда ходят юзеры.
		// Поэтому тёмные ноды вытаскивает зонд, а не самопроверка
		rescuer := destwatch.NewRescuer(rescueFleet{
			reg:   reg,
			fleet: fleetMgr,
			republish: func() {
				s := fleetMgr.Settings()
				srv.SetNodeConfig(s.Apply(
					defaultNodeConfig(s.RealityDest, s.TCPPort, s.XHTTPPort, s.PostQuantum)))
			},
		}, log.Printf)
		go leader.WhileLeading(ctx, elector, rescuer.Run)
	}

	// Правило Traefik держим сами: SNI в нём это dest ноды, а он меняется, и
	// вручную список протухает на первой же смене
	if kube != nil {
		routes := kubeingress.NewWatcher(kubeingress.Options{
			Client:  kube,
			Name:    *ingressRouteName,
			Service: *ingressService,
			Port:    uint32(*ingressPort),
			Source: func() []kubeingress.NodeRoute {
				out := make([]kubeingress.NodeRoute, 0)
				for _, n := range reg.List() {
					if !n.BehindProxy || n.RealityDest == "" {
						continue
					}
					out = append(out, kubeingress.NodeRoute{NodeID: n.ID, ServerName: n.RealityDest})
				}
				return out
			},
		})
		go leader.WhileLeading(ctx, elector, routes.Run)
	}

	if elector != nil {
		go elector.Run(ctx)
	}
	// Ротация, надзор и слежение за dest меняют состояние флота, поэтому идут
	// только у активной башки
	go leader.WhileLeading(ctx, elector, rotation.New(reg, srv, scoring).Run)
	go leader.WhileLeading(ctx, elector, enforcer.Run)
	go func() {
		<-ctx.Done()
		if panelServer != nil {
			panelServer.Stop()
		}
		if subServer != nil {
			_ = subServer.Close()
		}
		if provisionServer != nil {
			provisionServer.Stop()
		}
		// GracefulStop waits for active RPCs, and every agent session is a stream
		// that never ends on its own, so it would hang until systemd loses
		// patience and sends SIGKILL. Give the streams a bounded grace period,
		// then cut them
		done := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(shutdownGrace):
			log.Printf("head: %s grace elapsed with sessions still open, stopping hard", shutdownGrace)
			grpcServer.Stop()
		}
	}()
	// Отдельный слушатель для зондов: свой ключ, своя дверь. Без него отчёт о
	// достижимости идёт тем же секретом, что знает каждая нода флота
	if strings.TrimSpace(*probeListen) != "" && strings.TrimSpace(*probeSecret) != "" {
		probeSrv := grpc.NewServer(
			grpc.Creds(tokenaead.Server(*probeSecret)),
			grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
				MinTime:             10 * time.Second,
				PermitWithoutStream: true,
			}),
			grpc.KeepaliveParams(keepalive.ServerParameters{
				Time:    30 * time.Second,
				Timeout: 10 * time.Second,
			}),
		)
		fedpb.RegisterFederationServer(probeSrv, srv)
		probeLn, probeErr := net.Listen("tcp", *probeListen)
		if probeErr != nil {
			return probeErr
		}
		go func() {
			<-ctx.Done()
			probeSrv.Stop()
		}()
		go func() {
			if err := probeSrv.Serve(probeLn); err != nil {
				log.Printf("head: probe listener stopped: %v", err)
			}
		}()
		log.Printf("federation head probe listener on %s", *probeListen)
	}
	log.Printf("federation head listening on %s, advertising %s", *listen, endpoint)
	return grpcServer.Serve(ln)
}

// pickDest scans for a host worth borrowing a TLS identity from.
//
// The verdict comes from completing a real REALITY handshake, because nothing
// observable at the TLS layer predicts one: a 3995-byte handshake carries the
// ML-DSA-65 signature while a 4879-byte one does not, and a host can pass every
// TLS check and still fail REALITY outright. Without an xray to test with, the
// scan still picks a dest but refuses to claim post-quantum works
// scanPool probes the candidate list and returns what held up. Shared by the
// one-off pick at startup and by the watcher that keeps the dest alive.
func scanPool(ctx context.Context, pool string) []*scan.Result {
	candidates := scan.DefaultPool()
	if strings.TrimSpace(pool) != "" {
		candidates = splitList(pool)
	}
	results := scan.ProbeAll(ctx, candidates, 8, scan.DefaultTimeout)
	if extra := scan.ExpandSANs(results); len(extra) > 0 {
		results = append(results, scan.ProbeAll(ctx, extra, 8, scan.DefaultTimeout)...)
	}
	return results
}

func pickDest(pool, binDir string) (string, bool, error) {
	candidates := scan.DefaultPool()
	if strings.TrimSpace(pool) != "" {
		candidates = splitList(pool)
	}
	ctx := context.Background()
	log.Printf("head: scanning %d reality candidates", len(candidates))
	results := scan.ProbeAll(ctx, candidates, 8, scan.DefaultTimeout)

	// Every name a verified certificate covers is a usable dest of its own, and
	// they look like entirely different destinations to anyone watching
	if extra := scan.ExpandSANs(results); len(extra) > 0 {
		results = append(results, scan.ProbeAll(ctx, extra, 8, scan.DefaultTimeout)...)
	}

	if xrayPath, ok := binfetch.New(binDir).Installed("xray"); ok {
		verifier := scan.NewVerifier(xrayPath, filepath.Join(os.TempDir(), "wingsv-fed-scan"))
		for _, r := range results {
			if !r.Feasible {
				continue
			}
			if err := verifier.Verify(ctx, r); err != nil {
				log.Printf("head: could not verify %s: %v", r.Target, err)
			}
		}
	} else {
		log.Printf("head: no xray in %s, picking a dest on the tls check alone and leaving ML-DSA-65 off", binDir)
	}

	best := scan.Best(results)
	if best == nil {
		best = firstFeasible(results)
	}
	if best == nil {
		return "", false, errors.New("no usable reality dest found")
	}
	log.Printf("head: reality dest %s (post-quantum %v)", best.Target, best.PostQuantumOK)
	return best.Target, best.PostQuantumOK, nil
}

// firstFeasible is the fallback when nothing was verified: a dest that passed the
// TLS check is a guess, so post-quantum stays off
func firstFeasible(results []*scan.Result) *scan.Result {
	for _, r := range results {
		if r.Feasible {
			return r
		}
	}
	return nil
}

// startSubscriptions serves the client-facing subscription. Plain HTTP on
// loopback by default: the public origin is the panel's, which already terminates
// TLS, and a second certificate to keep in step buys nothing
func startSubscriptions(listen string, alloc *allocator.Allocator, head, release string, gate subs.Devices, onSilent func(string), turnPath func() subs.TurnSettings, quota func(string) uint64) (*http.Server, error) {
	if strings.TrimSpace(listen) == "" {
		log.Printf("head: no -sub-listen, subscriptions disabled")
		return nil, nil
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	subsHandler := subs.NewHandler(alloc)
	if turnPath != nil {
		subsHandler.SetTurnSettings(turnPath)
	}
	if gate != nil {
		subsHandler.SetDevices(gate, onSilent)
	}
	if quota != nil {
		subsHandler.SetQuota(quota)
	}
	subsHandler.Register(mux)
	subs.RegisterInstaller(mux, head, release)
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("head: subscriptions stopped: %v", err)
		}
	}()
	log.Printf("federation head subscriptions listening on %s", listen)
	return server, nil
}

// subscriptionBase is the origin a client sees. Falling back to the listen
// address keeps a single-host install working; a real deployment sets it
func subscriptionBase(base, listen string) string {
	if b := strings.TrimSpace(base); b != "" {
		return b
	}
	return "http://" + listen
}

// startPanelServer brings up the panel side, or reports why it stayed down. A
// missing secret disables it loudly rather than falling back to the fleet secret
func startPanelServer(listen, secret string, srv *headserver.Server, intakeSrv *intake.Server) (*grpc.Server, error) {
	if strings.TrimSpace(listen) == "" {
		return nil, nil
	}
	if strings.TrimSpace(secret) == "" {
		log.Printf("head: no -panel-secret, panel API disabled")
		return nil, nil
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	server := grpc.NewServer(grpc.Creds(tokenaead.Server(secret)))
	headpb.RegisterFederationHeadServer(server, srv)
	// Приём от клиента едет по тому же каналу: панель уже с ним говорит, а
	// второй порт это второй способ проебаться с доступом
	if intakeSrv != nil {
		intakepb.RegisterIntakeServer(server, intakeSrv)
	}
	go func() {
		if err := server.Serve(ln); err != nil {
			log.Printf("head: panel API stopped: %v", err)
		}
	}()
	log.Printf("federation head panel API listening on %s", listen)
	return server, nil
}

// defaultNodeConfig is the one config every node serves until per-node
// assignment lands. Vision on tcp and empty flow on xhttp is not a style choice:
// VLESS refuses a vision account whose client sent an empty flow
func defaultNodeConfig(dest string, tcpPort, xhttpPort uint32, postQuantum bool) *fedpb.NodeConfig {
	host := dest
	if h, _, err := net.SplitHostPort(dest); err == nil {
		host = h
	}
	return &fedpb.NodeConfig{
		Version: 1,
		Reality: &fedpb.RealityIdentity{
			Dest:        dest,
			ServerNames: []string{host},
			ShortIds:    []string{"0123456789abcdef"},
			PostQuantum: postQuantum,
		},
		Inbounds: []*fedpb.InboundSpec{
			{Tag: "fed-tcp", Network: "tcp", Port: tcpPort, Flow: "xtls-rprx-vision", Reality: true},
			{Tag: "fed-xhttp", Network: "xhttp", Port: xhttpPort, Reality: true,
				Xhttp: &fedpb.XhttpSpec{Path: "/", Mode: "auto"}},
		},
		Sniff: &fedpb.SniffPolicy{Enabled: true, DestOverride: []string{"http", "tls", "quic"}},
		Routing: &fedpb.RoutingPolicy{
			BlockBittorrent: true,
			BlockPrivate:    true,
			BlockedPorts:    []uint32{25, 465, 587},
		},
	}
}

// podIdentity - кто держит лизу. Имя пода узнаваемо в kubectl, hostname внутри
// пода совпадает с ним
func podIdentity() string {
	if name := os.Getenv("POD_NAME"); name != "" {
		return name
	}
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

// startProvisioning поднимает сервис, которым релей на ноде спрашивает башку,
// кому выдавать wg-пир. Отдельный порт, потому что релей не умеет tokenaead:
// он ходит открытым h2c с bearer-токеном флота
// fleetLinks достаёт пул ссылок из настроек флота на каждый провижн: оператор
// правит их в панели, и ждать перезапуска головы ради этого незачем
type fleetLinks struct{ mgr *fleet.Manager }

func (f fleetLinks) VKLinks() []string { return f.mgr.Settings().VKLinks }

func startProvisioning(
	listen, secret string,
	alloc *allocator.Allocator,
	peers provision.Peers,
	links provision.Links,
) (*grpc.Server, error) {
	if strings.TrimSpace(listen) == "" || strings.TrimSpace(secret) == "" {
		log.Printf("head: provisioning disabled, VK TURN will not be handed out")
		return nil, nil
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(bearerOnly(secret)))
	provisionSrv := provision.New(alloc)
	// Релей отчитывается о выданном пире вторым заходом в ту же ручку, и вот
	// тут наконец видно, чей это ключ
	if peers != nil {
		provisionSrv.SetPeers(peers)
	}
	// Пул VK-ссылок раздаётся тем же ответом: приложение складывает его к своим,
	// и одна сдохшая ссылка перестаёт означать потерю связи
	if links != nil {
		provisionSrv.SetLinks(links)
	}
	provisioningpb.RegisterProvisioningServer(server, provisionSrv)
	go func() {
		if err := server.Serve(ln); err != nil {
			log.Printf("head: provisioning stopped: %v", err)
		}
	}()
	log.Printf("federation head provisioning listening on %s", listen)
	return server, nil
}

// bearerOnly пускает только с токеном флота. Проверка стоит перед обработчиком,
// а не внутри: сервис отвечает на вопрос "кому выдавать доступ", и пускать к
// нему кого попало нельзя
func bearerOnly(secret string) grpc.UnaryServerInterceptor {
	want := "Bearer " + secret
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no credentials")
		}
		for _, value := range md.Get("authorization") {
			if subtle.ConstantTimeCompare([]byte(value), []byte(want)) == 1 {
				return handler(ctx, req)
			}
		}
		return nil, status.Error(codes.Unauthenticated, "no credentials")
	}
}

// domainHistory переводит строки хранилища в то, что показывает панель. Слои
// держатся врозь нарочно, чтобы схема базы не протекала в контракт
type domainHistory struct {
	store *pgstore.DomainStore
}

func (d domainHistory) TopDomainsPage(subjectID string, since time.Time, limit, offset int) ([]headserver.DomainStat, int64, error) {
	rows, total, err := d.store.TopDomainsPage(subjectID, since, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	out := make([]headserver.DomainStat, 0, len(rows))
	for _, r := range rows {
		out = append(out, headserver.DomainStat{
			Domain: r.Domain, Hits: r.Hits,
			UpBytes: r.UpBytes, DownBytes: r.DownBytes, LastSeen: r.LastSeen,
		})
	}
	return out, total, nil
}

// bandDevices выдаёт число устройств по текущей полосе доверия
type bandDevices struct {
	enforcer *enforce.Enforcer
}

func (b bandDevices) DevicesFor(subjectID string) int {
	return b.enforcer.Band(subjectID).DevicesFor()
}

// freshSightings переводит строки хранилища во вход разбора
type freshSightings struct {
	store *pgstore.DomainStore
}

func (f freshSightings) FreshPorts(since time.Time, limit int) ([]domainrules.SubjectPorts, error) {
	rows, err := f.store.PortsSince(since, limit)
	if err != nil {
		return nil, err
	}
	out := make([]domainrules.SubjectPorts, 0, len(rows))
	for _, r := range rows {
		out = append(out, domainrules.SubjectPorts{
			SubjectID: r.SubjectID,
			Hit: features.PortHit{
				Port: uint32(r.Port), Count: uint32(r.Count),
				DistinctTargets: uint32(r.DistinctTargets),
				UpBytes:         uint64(r.UpBytes), DownBytes: uint64(r.DownBytes),
			},
		})
	}
	return out, nil
}

func (f freshSightings) FreshPrints(since time.Time, limit int) ([]domainrules.SubjectPrint, error) {
	rows, err := f.store.PrintsSince(since, limit)
	if err != nil {
		return nil, err
	}
	out := make([]domainrules.SubjectPrint, 0, len(rows))
	for _, r := range rows {
		out = append(out, domainrules.SubjectPrint{
			SubjectID: r.SubjectID,
			Hit:       features.PrintHit{JA4: r.JA4, Count: uint32(r.Count)},
		})
	}
	return out, nil
}

func (f freshSightings) Fresh(since time.Time, limit int) ([]domainrules.Sighting, error) {
	rows, err := f.store.Since(since, limit)
	if err != nil {
		return nil, err
	}
	// Строки сворачиваются по домену: ритм виден только на разнице между первым
	// и последним обращением, а в отдельной строке она нулевая
	type key struct{ subject, domain string }
	folded := map[key]*domainrules.Sighting{}
	order := make([]key, 0, len(rows))
	for _, r := range rows {
		k := key{subject: r.SubjectID, domain: r.Domain}
		entry, ok := folded[k]
		if !ok {
			entry = &domainrules.Sighting{
				SubjectID: r.SubjectID, Domain: r.Domain, Port: uint32(r.Port),
				FirstSeen: r.At, LastSeen: r.At,
			}
			folded[k] = entry
			order = append(order, k)
		}
		entry.Count += uint32(r.Count)
		entry.UpBytes += uint64(r.UpBytes)
		entry.DownBytes += uint64(r.DownBytes)
		entry.LongLived += uint32(r.LongLived)
		if r.At.Before(entry.FirstSeen) {
			entry.FirstSeen = r.At
		}
		if r.At.After(entry.LastSeen) {
			entry.LastSeen = r.At
		}
	}
	out := make([]domainrules.Sighting, 0, len(order))
	for _, k := range order {
		out = append(out, *folded[k])
	}
	return out, nil
}

// HourlyLoad собирает почасовую нагрузку по субъектам. Дни берутся максимумом
// по часам: это число суток, в которые самый устойчивый час был занят, а
// суточный разбор именно про устойчивость и спрашивает
func (f freshSightings) HourlyLoad(since time.Time) ([]features.HourlyLoad, error) {
	rows, err := f.store.HourlyLoad(since)
	if err != nil {
		return nil, err
	}
	bySubject := map[string]*features.HourlyLoad{}
	order := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Hour < 0 || r.Hour > 23 {
			continue
		}
		entry, ok := bySubject[r.SubjectID]
		if !ok {
			entry = &features.HourlyLoad{SubjectID: r.SubjectID}
			bySubject[r.SubjectID] = entry
			order = append(order, r.SubjectID)
		}
		entry.Hits[r.Hour] += uint64(r.Hits)
		if days := float64(r.Days); days > entry.Days {
			entry.Days = days
		}
	}
	out := make([]features.HourlyLoad, 0, len(order))
	for _, id := range order {
		out = append(out, *bySubject[id])
	}
	return out, nil
}

// stakeSweepEvery - как часто обходим личные счета доноров. Чаще незачем: залог
// вносят раз в жизни, а каждый обход это запрос в цепочку на каждого донора
const stakeSweepEvery = 2 * time.Minute

// newChainPublisher поднимает публикатора эпох.
//
// Ключ лежит файлом в том же виде, в каком его пишет solana-keygen: массив из
// 64 чисел. Держать его в переменной окружения нельзя нахуй - он утечёт в первый
// же дамп процесса
func newChainPublisher(endpoint, program, keyPath string) (*chain.Publisher, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("keypair file is unreadable: %w", err)
	}
	var numbers []byte
	if err := json.Unmarshal(raw, &numbers); err != nil {
		return nil, fmt.Errorf("keypair does not parse: %w", err)
	}
	signer, err := chain.NewSigner(numbers)
	if err != nil {
		return nil, err
	}
	decoded, err := payout.DecodeBase58(program)
	if err != nil {
		return nil, fmt.Errorf("program address does not parse: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("program address is %d bytes, want 32", len(decoded))
	}
	var id chain.Pubkey
	copy(id[:], decoded)
	return chain.NewPublisher(chain.New(endpoint), signer, id, log.Printf), nil
}

// sweepEvery - как часто заносы уносятся в казну. Реже - и человек, занёсший
// денег, полдня не видит их в общем котле; чаще - и мы платим за транзакцию
// чаще, чем приходят деньги
const sweepEvery = 10 * time.Minute

func sweepDonations(ctx context.Context, publisher *chain.Publisher, mint chain.Pubkey) {
	ticker := time.NewTicker(sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		call, cancel := context.WithTimeout(ctx, time.Minute)
		signature, amount, err := publisher.SweepDonations(call, mint)
		cancel()
		switch {
		case err != nil:
			log.Printf("head: donations did not reach the treasury: %v", err)
		case amount > 0:
			log.Printf("head: %d micro-USDT of donations went to the treasury: %s", amount, signature)
		}
	}
}
