package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/agent/geo"
	"wingsnet.org/federation/internal/agent/headrelay"
	"wingsnet.org/federation/internal/agent/passport"
	"wingsnet.org/federation/internal/agent/receiptdoor"
	"wingsnet.org/federation/internal/agent/shaper"
	"wingsnet.org/federation/internal/agent/state"
	"wingsnet.org/federation/internal/agent/supervisor"
	"wingsnet.org/federation/internal/agent/vktpctl"
	"wingsnet.org/federation/internal/agent/wgwatch"
	"wingsnet.org/federation/internal/agent/xraycfg"
	"wingsnet.org/federation/internal/common/tokenaead"
	"wingsnet.org/federation/pkg/agentclient"
)

func runAgent(args []string) error {
	fs := newFlagSet("agent")
	statePath := fs.String("state", state.DefaultPath, "path to the node identity")
	binDir := fs.String("bin-dir", "/usr/local/wings/federation/bin", "where supervised binaries live")
	configDir := fs.String("config-dir", "/etc/wings/federation", "where the rendered xray config goes")
	stateDir := fs.String("state-dir", state.StateDir, "where the node keeps mutable state")
	relayGRPC := fs.String("relay-grpc", "127.0.0.1:25612", "local relay management endpoint")
	relayToken := fs.String("relay-token", "", "token for the local relay management api")
	xrayURL := fs.String("xray-url", "", "where to fetch the xray build")
	xraySHA := fs.String("xray-sha512", "", "expected sha512 of the xray build")
	// Enrolment on first start, for containers. A container has no installer to
	// run enroll for it, and its filesystem is usually empty on first boot.
	head := fs.String("head", "", "federation head endpoint, for enrolling on first start")
	token := fs.String("enroll-token", "", "enroll token, used only when there is no identity yet")
	budgetGB := fs.Uint64("budget-gb", 0, "monthly traffic to donate, in GiB, when enrolling")
	salt := fs.String("salt", "", "fingerprint salt, to split hosts cloned from one image")
	donor := fs.String("donor", "", "optional donor hint, when enrolling")
	asn := fs.String("asn", "", "provider ASN, when enrolling")
	country := fs.String("country", "", "two-letter country code, when enrolling")
	ports := newPortList()
	fs.Var(ports, "ports", "comma-separated ports to offer, when enrolling")
	exclude := newPortList()
	fs.Var(exclude, "exclude-ports", "ports to skip even though they bind, e.g. one held by a kubernetes hostPort")
	behindProxy := fs.Bool("behind-proxy", false, "a proxy in front terminates the port and passes the client address in a PROXY protocol header")
	publicPort := fs.Uint("public-port", 0, "the port clients dial when a proxy is in front")
	addresses := newStringList()
	fs.Var(addresses, "address", "public address to pin, repeatable, when enrolling")
	// Труба для зондов: адрес башки блокируют, а нода доступна по определению,
	// иначе через неё не ходили бы люди. Байты идут насквозь, читать их нода не
	// может - у зонда свой ключ
	wgIface := fs.String("wg-interface", "wg0", "kernel wireguard interface the relay programs peers onto")
	relayProbes := fs.String("probe-relay-listen", "", "listen address that lets vantage points reach the head through this node")
	receiptPort := fs.Int("receipt-door-port", xraycfg.ReceiptDoorPort,
		"port for receipts from clients inside this node's own tunnel (0 disables)")
	// Ведёт труба на ПРОБНУЮ дверь башки, а не на агентскую: у зонда свой ключ,
	// и агентский слушатель его не поймёт
	relayHead := fs.String("probe-relay-head", "", "head address the relay dials; empty reuses this node's own head endpoint")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	st, err := state.Load(*statePath)
	// An identity on disk always wins. Re-enrolling a node that already has one
	// would burn a second token and register a duplicate every time a container
	// restarts, so the token is read only when there is nothing to load.
	if errors.Is(err, state.ErrNotEnrolled) && strings.TrimSpace(*token) != "" {
		log.Printf("agent: no identity at %s, enrolling with the head", *statePath)
		st, err = enroll(context.Background(), enrollParams{
			Head:         *head,
			Token:        *token,
			BudgetGB:     *budgetGB,
			Salt:         *salt,
			StatePath:    *statePath,
			Donor:        *donor,
			Ports:        ports.ports,
			ExcludePorts: exclude.ports,
			BehindProxy:  *behindProxy,
			PublicPort:   uint32(*publicPort),
			Addresses:    addresses.values,
			ASN:          *asn,
			Country:      *country,
		})
	}
	if err != nil {
		return err
	}

	bootID, err := newBootID()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sup := supervisor.New(supervisor.Options{
		BinDir:     *binDir,
		ConfigDir:  *configDir,
		StateDir:   *stateDir,
		XrayURL:    *xrayURL,
		XraySHA512: *xraySHA,
	})
	defer func() { _ = sup.Stop() }()

	// The relay is optional: a node can serve Xray alone, and a relay that is
	// not up yet must not stop the agent from reporting
	if *relayToken != "" {
		if relay, err := vktpctl.Dial(*relayGRPC, *relayToken); err == nil {
			sup.AttachRelay(relay)
			defer func() { _ = relay.Close() }()
			// Порт данных выбирает нода, а не конфиг: он выводится из отпечатка
			// и открывается на хосте здесь же. Иначе релей слушает, а хост с
			// политикой DROP молча съедает весь DTLS.
			//
			// Следим, а не ставим один раз: при старте пода релей ещё не поднял
			// свой gRPC, да и переживает он нас не по разу
			go sup.WatchRelayPort(ctx, st.Fingerprint)
		} else {
			log.Printf("agent: relay control unavailable: %v", err)
		}
	}

	// Гео качается в фоне: база весит десятки MB, и нода должна выйти на связь
	// раньше, чем она доедет. Ключи только из окружения
	go func() {
		keys := geo.Keys{MaxMind: os.Getenv("WINGSV_MAXMIND_KEY"), DBIP: os.Getenv("WINGSV_DBIP_KEY")}
		if err := sup.StartGeo(ctx, keys); err != nil {
			log.Printf("agent: geo database unavailable: %v", err)
		}
	}()

	log.Printf("agent %s starting, head %s", st.NodeID, st.HeadEndpoint)
	// Скорость пиров режет ядро: у релея ограничителя нет ни в API, ни внутри
	if iface := strings.TrimSpace(*wgIface); iface != "" {
		sup.SetShaper(shaper.New(iface))
		// Куда ходят клиенты VK TURN, видно только тут: у релея нет ни sniffing,
		// ни access-лога, а с wg-интерфейса выходит уже расшифрованный трафик
		watcher := wgwatch.New(iface, func(s wgwatch.Sighting) {
			sup.ObserveRelaySighting(s.Address, s.Domain, s.JA3, s.JA4, s.At)
		})
		watcher.SetLogger(log.Printf)
		go watcher.Run(ctx)
	}
	// Дверь для расписок тех, кому до панели снаружи не достучаться. Наружу не
	// торчит: петля для Xray и адрес ноды внутри wg для VK TURN
	if *receiptPort > 0 {
		door := receiptdoor.New()
		door.SetLogger(log.Printf)
		sup.SetReceiptDoor(door)
		addresses := []string{fmt.Sprintf("127.0.0.1:%d", *receiptPort)}
		if wg := strings.TrimSpace(*wgIface); wg != "" {
			if addr := interfaceAddress(wg); addr != "" {
				addresses = append(addresses, fmt.Sprintf("%s:%d", addr, *receiptPort))
			}
		}
		door.Serve(ctx, addresses)
	}
	if listen := strings.TrimSpace(*relayProbes); listen != "" {
		target := strings.TrimSpace(*relayHead)
		if target == "" {
			target = st.HeadEndpoint
		}
		go headrelay.New(listen, target, log.Printf).Run(ctx)
	}
	return agentclient.Run(ctx, agentclient.Config{
		HeadEndpoint: st.HeadEndpoint,
		NodeID:       st.NodeID,
		NodeSecret:   st.NodeSecret,
		BootID:       bootID,
		AgentVersion: resolveVersion(),
		Passport:     nodePassport(sup),
		Dial: func(_ context.Context, endpoint string) (*grpc.ClientConn, error) {
			// Keepalive обязателен: башка живёт за NodePort, при переезде пода
			// запись DNAT протухает, и стрим остаётся установленным с точки
			// зрения обеих сторон, ничего не передавая
			return grpc.NewClient(endpoint,
				grpc.WithTransportCredentials(tokenaead.Client(st.FleetSecret)),
				grpc.WithKeepaliveParams(keepalive.ClientParameters{
					Time:                20 * time.Second,
					Timeout:             10 * time.Second,
					PermitWithoutStream: true,
				}))
		},
	}, sup)
}

// newBootID marks this run. A changed value tells the head the counters restarted
// so the delta is not billed to the donor
func newBootID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// nodePassport собирает паспорт со страной, определённой по внешнему адресу.
// Заявленная строка врёт ровно так же часто, как ошибается, а имя сервера
// человек читает глазами
func nodePassport(sup *supervisor.Supervisor) *fedpb.NodePassport {
	relayIP := sup.RelayPublicIP()
	card := passport.Collect(resolveVersion(), relayIP)
	country := sup.Country(relayIP)
	if country == "" {
		for _, addr := range card.GetAddresses() {
			if country = sup.Country(addr.GetAddress()); country != "" {
				break
			}
		}
	}
	if country != "" {
		card.Country = country
	}
	return card
}

// interfaceAddress - адрес ноды внутри туннеля. По нему клиенты VK TURN и
// стучатся: наружу этот адрес не виден, а из туннеля доступен всегда
func interfaceAddress(name string) string {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addresses, err := link.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addresses {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}
