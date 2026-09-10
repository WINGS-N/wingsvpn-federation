package main

import (
	"context"
	"errors"
	"log"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/agent/binfetch"
	"wingsnet.org/federation/internal/common/tokenaead"
	"wingsnet.org/federation/internal/probe"
)

// runProbe is the vantage-point role: a machine inside the censored network that
// measures nodes the way a real user reaches them.
//
// It holds no node credential and no user identity: the head mints it a profile
// of its own on each node, so a seized vantage point gives up nothing but the
// ability to measure
func runProbe(args []string) error {
	fs := newFlagSet("probe")
	head := fs.String("head", "", "federation head endpoint, host:port")
	secret := fs.String("secret", "", "secret keying the transport to the head")
	// Через ноды зонд ходит, когда прямой адрес башки закрыт. Порт тот, что
	// нода подставляет под -probe-relay-listen
	relayPort := fs.Int("relay-port", 0, "port where nodes let this probe reach the head; 0 disables the fallback")
	relayCache := fs.String("relay-cache", "/var/lib/wings/federation/relays", "where learned relay paths are kept")
	// Пути из задания зонд узнаёт по сессии, а сессии может и не быть вовсе:
	// закрыли адрес башки - и он не узнает про ноды никогда. Поэтому первые
	// адреса задаются руками, дальше список пополняется сам
	relays := newStringList()
	fs.Var(relays, "relay", "node address that relays this probe to the head, repeatable")
	probeID := fs.String("id", "", "stable identifier for this vantage point")
	region := fs.String("region", "", "where this vantage point sits")
	isp := fs.String("isp", "", "the ISP it observes from")
	asn := fs.String("asn", "", "the ASN it observes from")
	binDir := fs.String("bin-dir", "/usr/local/wings/federation/bin", "where the xray binary lives")
	workDir := fs.String("work-dir", "/var/lib/wings/federation/probe", "scratch space for rendered configs")
	socksPort := fs.Int("socks-port", 41080, "loopback port the measured tunnel is offered on")
	xrayURL := fs.String("xray-url", "", "where to fetch the xray build if it is missing")
	xraySHA := fs.String("xray-sha512", "", "expected sha512 of that build")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*head) == "" || strings.TrimSpace(*secret) == "" {
		return errors.New("both -head and -secret are required")
	}
	if strings.TrimSpace(*probeID) == "" {
		return errors.New("-id is required: reports are filed against it")
	}

	fetcher := binfetch.New(*binDir)
	xrayPath, ok := fetcher.Installed("xray")
	if !ok {
		if *xrayURL == "" {
			return errors.New("no xray binary and no -xray-url to fetch one; a probe measures through xray")
		}
		path, err := fetcher.Fetch(*xrayURL, "xray", *xraySHA)
		if err != nil {
			return err
		}
		xrayPath = path
	}

	measurer := probe.NewMeasurer(xrayPath, filepath.Clean(*workDir), *socksPort)
	cfg := probe.Config{
		HeadEndpoint: *head,
		ProbeID:      *probeID,
		Region:       *region,
		ISP:          *isp,
		ASN:          *asn,
		Version:      resolveVersion(),
		Dial: func(_ context.Context, endpoint string) (*grpc.ClientConn, error) {
			// Keepalive обязателен: башка живёт за NodePort, при переезде пода
			// запись DNAT протухает, и стрим остаётся установленным с точки
			// зрения обеих сторон, ничего не передавая
			return grpc.NewClient(endpoint,
				grpc.WithTransportCredentials(tokenaead.Client(*secret)),
				grpc.WithKeepaliveParams(keepalive.ClientParameters{
					Time:                20 * time.Second,
					Timeout:             10 * time.Second,
					PermitWithoutStream: true,
				}))
		},
		Measure: func(ctx context.Context, target *fedpb.ProbeTarget) *fedpb.ProbeReport {
			return measurer.Measure(ctx, target)
		},
		RelayPort:  *relayPort,
		RelayCache: *relayCache,
		Relays:     relays.values,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("probe %s measuring for %s", *probeID, *head)
	return probe.Run(ctx, cfg)
}

func runDoctor(args []string) error {
	fs := newFlagSet("doctor")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return printDoctor()
}
