package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/agent/passport"
	"wingsnet.org/federation/internal/agent/portpick"
	"wingsnet.org/federation/internal/agent/state"
	"wingsnet.org/federation/internal/common/tokenaead"
	"wingsnet.org/federation/internal/head/tokens"
	"wingsnet.org/federation/pkg/nodeid"
)

// runEnroll joins the federation once and writes the identity to disk.
//
// It lives in the binary rather than the installer because the shell must never
// handle a credential
func runEnroll(args []string) error {
	fs := newFlagSet("enroll")
	head := fs.String("head", "", "federation head endpoint, host:port")
	token := fs.String("token", "", "single-use enroll token")
	budgetGB := fs.Uint64("budget-gb", 0, "monthly traffic to donate, in GiB")
	salt := fs.String("salt", "", "fingerprint salt, to split hosts cloned from one image")
	statePath := fs.String("state", state.DefaultPath, "where to write the node identity")
	donor := fs.String("donor", "", "optional donor hint")
	ports := newPortList()
	fs.Var(ports, "ports", "comma-separated ports to offer")
	exclude := newPortList()
	fs.Var(exclude, "exclude-ports", "ports to skip even though they bind, e.g. one held by a kubernetes hostPort")
	behindProxy := fs.Bool("behind-proxy", false, "a proxy in front terminates the port and passes the client address in a PROXY protocol header")
	publicPort := fs.Uint("public-port", 0, "the port clients dial when a proxy is in front; goes into the links instead of the listening one")
	addresses := newStringList()
	fs.Var(addresses, "address", "public address to pin, repeatable; needed behind NAT or a floating IP")
	asn := fs.String("asn", "", "provider ASN, so a user is not handed two nodes on one network")
	country := fs.String("country", "", "two-letter country code")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	saved, err := enroll(context.Background(), enrollParams{
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
	if err != nil {
		return err
	}

	// Machine-readable last line: the installer echoes it and the exit code is
	// the actual contract
	fmt.Printf("enrolled node=%s head=%s\n", saved.NodeID, saved.HeadEndpoint)
	return nil
}

// enrollParams is everything Join needs. It exists so the agent can enrol
// itself on first start through the same code path rather than a second copy
// of it that drifts.
type enrollParams struct {
	Head      string
	Token     string
	BudgetGB  uint64
	Salt      string
	StatePath string
	Donor     string
	Ports     []uint32
	// ExcludePorts - порты, которые связываются, но не работают: в кубере
	// hostPort перехватывает пакеты правилом DNAT, а bind при этом проходит
	ExcludePorts []uint32
	// BehindProxy: перед нодой прокси, отдающий адрес клиента заголовком
	BehindProxy bool
	// PublicPort - порт прокси, куда стучится клиент
	PublicPort uint32
	Addresses  []string
	ASN        string
	Country    string
}

func enroll(parent context.Context, p enrollParams) (*state.State, error) {
	if strings.TrimSpace(p.Head) == "" || strings.TrimSpace(p.Token) == "" {
		return nil, errors.New("both -head and -token are required")
	}
	// Somebody always pastes the placeholder out of the docs
	if strings.HasPrefix(p.Token, "<") {
		return nil, errors.New("that is the placeholder, not a token")
	}
	if p.BudgetGB == 0 {
		return nil, errors.New("-budget-gb is required: a node with no declared budget cannot be scheduled")
	}

	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	fleetSecret, enrollToken, err := tokens.SplitCompound(p.Token)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(p.Head, grpc.WithTransportCredentials(tokenaead.Client(fleetSecret)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	offered := p.Ports
	if len(offered) == 0 {
		// Nobody said which ports to take, so find out rather than assume. The
		// head renders this node's inbounds and its vless links against exactly
		// what is reported here, so guessing 443 on a host that cannot bind it
		// would enrol a node that serves nothing.
		// Отпечаток как зерно: порт держится за ноду, а не за запуск процесса,
		// иначе после перезапуска башка проверяла бы адрес, которого уже нет
		tcp, xhttp, err := portpick.Auto(nodeid.Fingerprint(p.Salt), p.ExcludePorts...)
		if err != nil {
			return nil, fmt.Errorf("no free port for the inbounds: %w", err)
		}
		offered = []uint32{tcp, xhttp}
		if tcp != portpick.TCPDefaults[0] {
			log.Printf("enroll: %d is taken, offering %d instead - derived from this host, not from a published list",
				portpick.TCPDefaults[0], tcp)
		}
	}

	fingerprint := nodeid.Fingerprint(p.Salt)
	resp, err := fedpb.NewFederationClient(conn).Join(ctx, &fedpb.JoinRequest{
		EnrollToken:     enrollToken,
		NodeFingerprint: fingerprint,
		Passport: passport.CollectWith(resolveVersion(),
			passport.Declared{ASN: p.ASN, Country: p.Country}, p.Addresses...),
		DeclaredMonthlyBudgetBytes: p.BudgetGB << 30,
		OfferedPorts:               offered,
		BehindProxy:                p.BehindProxy,
		PublicPort:                 p.PublicPort,
		DonorHint:                  p.Donor,
	})
	if err != nil {
		return nil, err
	}
	if resp.GetError() != "" {
		return nil, errors.New(resp.GetError())
	}

	endpoint := resp.GetHeadEndpoint()
	if strings.TrimSpace(endpoint) == "" {
		endpoint = p.Head
	}
	saved := &state.State{
		NodeID:       resp.GetNodeId(),
		NodeSecret:   resp.GetNodeSecret(),
		FleetSecret:  fleetSecret,
		HeadEndpoint: endpoint,
		Fingerprint:  fingerprint,
		DonorHint:    p.Donor,
	}
	if err := state.Save(p.StatePath, saved); err != nil {
		return nil, err
	}
	return saved, nil
}

type portList struct{ ports []uint32 }

func newPortList() *portList { return &portList{} }

func (p *portList) String() string { return "" }

func (p *portList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n uint32
		for _, c := range part {
			if c < '0' || c > '9' {
				return fmt.Errorf("bad port %q", part)
			}
			n = n*10 + uint32(c-'0')
		}
		p.ports = append(p.ports, n)
	}
	return nil
}

// stringList collects a repeatable flag
type stringList struct{ values []string }

func newStringList() *stringList { return &stringList{} }

func (s *stringList) String() string { return strings.Join(s.values, ",") }

func (s *stringList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			s.values = append(s.values, part)
		}
	}
	return nil
}
