package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	fedpb "wingsnet.org/federation/gen/fedpb"
)

// A head restart must not de-enroll the fleet: agents keep valid secrets, and a
// head that forgot them would reject every one of them at once. Usage counters
// have to survive too, or a restart hands every donor their spent budget back

// Store persists the registry
type Store interface {
	Load() ([]*Node, error)
	Save(nodes []*Node) error
}

// nopStore is used when no path was configured, for tests
type nopStore struct{}

func (nopStore) Load() ([]*Node, error) { return nil, nil }
func (nopStore) Save([]*Node) error     { return nil }

type persisted struct {
	ID                  string `json:"id"`
	Fingerprint         string `json:"fingerprint"`
	Secret              string `json:"secret"`
	DonorID             string `json:"donor_id"`
	PassportWire        []byte `json:"passport_wire,omitempty"`
	DeclaredBudgetBytes uint64 `json:"declared_budget_bytes"`
	State               int32  `json:"state"`
	Reason              string `json:"reason"`
	BootID              string `json:"boot_id"`
	LastUpBytes         uint64 `json:"last_up_bytes"`
	LastDownBytes       uint64 `json:"last_down_bytes"`
	UsedBytes           uint64 `json:"used_bytes"`
	LastProbeBytes      uint64 `json:"last_probe_bytes"`
	ProbeBytes          uint64 `json:"probe_bytes"`
	ConfigVersion       uint64 `json:"config_version"`
	JoinedAtUnix        int64  `json:"joined_at_unix"`
	// PeriodStartUnix has to survive a restart, or a head that comes back up
	// starts a fresh month and hands the donor a budget they already spent
	PeriodStartUnix int64    `json:"period_start_unix"`
	OfferedPorts    []uint32 `json:"offered_ports,omitempty"`
	BehindProxy     bool     `json:"behind_proxy,omitempty"`
	PublicPort      uint32   `json:"public_port,omitempty"`
	RealityDest     string   `json:"reality_dest,omitempty"`
	XrayVersion     string   `json:"xray_version,omitempty"`
	VktpVersion     string   `json:"vktp_version,omitempty"`
	RelayEndpoint   string   `json:"relay_endpoint,omitempty"`
	// The public halves of the node's inbound identity. Without them a restarted
	// head cannot rebuild a single share link until every node re-acks its config
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	Mldsa65Verify    string `json:"mldsa65_verify,omitempty"`
	// Probe results survive a restart. Without them a head that comes back has no
	// verified address for anybody and hands out nothing until the probes have
	// been round again
	Reachability []persistedReach `json:"reachability,omitempty"`
}

type persistedReach struct {
	Address     string `json:"address"`
	Transport   string `json:"transport"`
	OK          bool   `json:"ok"`
	HandshakeMs uint32 `json:"handshake_ms,omitempty"`
	RTTMs       uint32 `json:"rtt_ms,omitempty"`
	DownloadBps uint64 `json:"download_bps,omitempty"`
	Error       string `json:"error,omitempty"`
	ProbeID     string `json:"probe_id,omitempty"`
	AtUnix      int64  `json:"at_unix"`
}

// FileStore keeps the registry in one file
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore builds a store rooted at path
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// Load reads the registry, treating an absent file as an empty fleet
func (f *FileStore) Load() ([]*Node, error) {
	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rows []persisted
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	out := make([]*Node, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.node())
	}
	return out, nil
}

// Save writes the registry at 0600; it holds every node's secret
func (f *FileStore) Save(nodes []*Node) error {
	rows := make([]persisted, 0, len(nodes))
	for _, n := range nodes {
		rows = append(rows, newPersisted(n))
	}
	data, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	// Write and rename, so a head killed mid-save leaves the old registry intact
	// rather than a truncated one that de-enrolls everybody
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// node rebuilds the in-memory shape. Shared by every store so a new backend
// cannot quietly disagree with the old one about what a node is.
func (r persisted) node() *Node {
	n := &Node{
		ID:                  r.ID,
		Fingerprint:         r.Fingerprint,
		Secret:              r.Secret,
		DonorID:             r.DonorID,
		DeclaredBudgetBytes: r.DeclaredBudgetBytes,
		State:               fedpb.RotationState(r.State),
		Reason:              r.Reason,
		BootID:              r.BootID,
		LastUpBytes:         r.LastUpBytes,
		LastProbeBytes:      r.LastProbeBytes,
		ProbeBytes:          r.ProbeBytes,
		LastDownBytes:       r.LastDownBytes,
		UsedBytes:           r.UsedBytes,
		ConfigVersion:       r.ConfigVersion,
		JoinedAt:            time.Unix(r.JoinedAtUnix, 0),
		OfferedPorts:        r.OfferedPorts,
		BehindProxy:         r.BehindProxy,
		PublicPort:          r.PublicPort,
		XrayVersion:         r.XrayVersion,
		VktpVersion:         r.VktpVersion,
		RelayEndpoint:       r.RelayEndpoint,
		RealityDest:         r.RealityDest,
		RealityPublicKey:    r.RealityPublicKey,
		Mldsa65Verify:       r.Mldsa65Verify,
	}
	if r.PeriodStartUnix > 0 {
		n.PeriodStart = time.Unix(r.PeriodStartUnix, 0)
	}
	if len(r.Reachability) > 0 {
		n.Reachability = make(map[string]Reachability, len(r.Reachability))
		for _, reach := range r.Reachability {
			n.Reachability[ReachKey(reach.Address, reach.Transport)] = Reachability{
				Address:     reach.Address,
				Transport:   reach.Transport,
				OK:          reach.OK,
				HandshakeMs: reach.HandshakeMs,
				RTTMs:       reach.RTTMs,
				DownloadBps: reach.DownloadBps,
				Error:       reach.Error,
				ProbeID:     reach.ProbeID,
				At:          time.Unix(reach.AtUnix, 0),
			}
		}
	}
	if len(r.PassportWire) > 0 {
		p := &fedpb.NodePassport{}
		if proto.Unmarshal(r.PassportWire, p) == nil {
			n.Passport = p
		}
	}
	return n
}

// newPersisted is the other direction
func newPersisted(n *Node) persisted {
	r := persisted{
		ID:                  n.ID,
		Fingerprint:         n.Fingerprint,
		Secret:              n.Secret,
		DonorID:             n.DonorID,
		DeclaredBudgetBytes: n.DeclaredBudgetBytes,
		State:               int32(n.State),
		Reason:              n.Reason,
		BootID:              n.BootID,
		LastUpBytes:         n.LastUpBytes,
		LastProbeBytes:      n.LastProbeBytes,
		ProbeBytes:          n.ProbeBytes,
		LastDownBytes:       n.LastDownBytes,
		UsedBytes:           n.UsedBytes,
		ConfigVersion:       n.ConfigVersion,
		JoinedAtUnix:        n.JoinedAt.Unix(),
		OfferedPorts:        n.OfferedPorts,
		BehindProxy:         n.BehindProxy,
		PublicPort:          n.PublicPort,
		XrayVersion:         n.XrayVersion,
		VktpVersion:         n.VktpVersion,
		RelayEndpoint:       n.RelayEndpoint,
		RealityDest:         n.RealityDest,
		RealityPublicKey:    n.RealityPublicKey,
		Mldsa65Verify:       n.Mldsa65Verify,
	}
	if !n.PeriodStart.IsZero() {
		r.PeriodStartUnix = n.PeriodStart.Unix()
	}
	for _, reach := range n.Reachability {
		r.Reachability = append(r.Reachability, persistedReach{
			Address:     reach.Address,
			Transport:   reach.Transport,
			OK:          reach.OK,
			HandshakeMs: reach.HandshakeMs,
			RTTMs:       reach.RTTMs,
			DownloadBps: reach.DownloadBps,
			Error:       reach.Error,
			ProbeID:     reach.ProbeID,
			AtUnix:      reach.At.Unix(),
		})
	}
	if n.Passport != nil {
		if wire, err := proto.Marshal(n.Passport); err == nil {
			r.PassportWire = wire
		}
	}
	return r
}
