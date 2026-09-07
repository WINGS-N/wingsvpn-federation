package headserver

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fedpb "wingsnet.org/federation/gen/fedpb"
	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/fleet"
)

// FleetManager is what the panel drives through this server
type FleetManager interface {
	Settings() fleet.Settings
	Update(fleet.Settings) (fleet.Settings, error)
}

// ConfigPusher re-renders and re-sends the fleet config after a change
type ConfigPusher interface {
	SetNodeConfig(*fedpb.NodeConfig)
	CurrentConfig() *fedpb.NodeConfig
	Upgrade(nodeID, component, version, url, sha512 string, restartOnly bool) int
}

// SetFleet wires the settings manager and the server that pushes config
func (s *Server) SetFleet(mgr FleetManager, pusher ConfigPusher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fleet, s.pusher = mgr, pusher
}

// GetFleetSettings answers the panel
func (s *Server) GetFleetSettings(_ context.Context, _ *headpb.FleetSettingsRequest) (*headpb.FleetSettings, error) {
	s.mu.Lock()
	mgr := s.fleet
	s.mu.Unlock()
	if mgr == nil {
		return nil, status.Error(codes.Unavailable, "fleet settings are not configured on this head")
	}
	return toWire(mgr.Settings()), nil
}

// SetFleetSettings applies the operator's choice to every node.
//
// The new config version goes out on the nodes' next hello rather than being
// forced down the stream: a push restarts Xray, and doing that to the whole
// fleet at the moment somebody saves a form would drop every live connection at
// once.
func (s *Server) SetFleetSettings(_ context.Context, req *headpb.FleetSettings) (*headpb.FleetSettings, error) {
	s.mu.Lock()
	mgr, pusher := s.fleet, s.pusher
	s.mu.Unlock()
	if mgr == nil {
		return nil, status.Error(codes.Unavailable, "fleet settings are not configured on this head")
	}
	next := fromWire(req, mgr.Settings())
	if next.RealityDest == "" && !next.AutoDest {
		return nil, status.Error(codes.InvalidArgument,
			"reality dest or auto-pick is required: without it the node has nothing to present")
	}
	saved, err := mgr.Update(next)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if pusher != nil {
		if cfg := pusher.CurrentConfig(); cfg != nil {
			pusher.SetNodeConfig(saved.Apply(cfg))
		}
	}
	return toWire(saved), nil
}

// RestartComponent kicks Xray or the relay without changing a version
func (s *Server) RestartComponent(_ context.Context, req *headpb.RestartComponentRequest) (*headpb.RestartComponentResponse, error) {
	component := strings.TrimSpace(req.GetComponent())
	if component != "xray" && component != "vktp" {
		return nil, status.Error(codes.InvalidArgument, "component must be xray or vktp")
	}
	s.mu.Lock()
	pusher := s.pusher
	s.mu.Unlock()
	if pusher == nil {
		return nil, status.Error(codes.Unavailable, "this head cannot reach the fleet")
	}
	n := pusher.Upgrade(req.GetNodeId(), component, "", "", "", true)
	return &headpb.RestartComponentResponse{Nodes: uint32(n)}, nil
}

// normalizeVKLinks чистит пул: пустые строки и дубли в нём означают ссылку,
// которую приложение будет честно пробовать вхолостую
func normalizeVKLinks(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, link := range raw {
		trimmed := strings.TrimSpace(link)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		out = append(out, trimmed)
	}
	return out
}

func toWire(s fleet.Settings) *headpb.FleetSettings {
	return &headpb.FleetSettings{
		Xray:          &headpb.BuildChoice{Version: s.XrayVersion, Url: s.XrayURL, Sha512: s.XraySHA512},
		Vktp:          &headpb.BuildChoice{Version: s.VKTPVersion, Url: s.VKTPURL, Sha512: s.VKTPSHA512},
		AutoUpgrade:   s.AutoUpgrade,
		RealityDest:   s.RealityDest,
		AutoDest:      s.AutoDest,
		PostQuantum:   s.PostQuantum,
		TcpPort:       s.TCPPort,
		XhttpPort:     s.XHTTPPort,
		ConfigVersion: s.ConfigVersion,
		DestPoolSize:  uint32(len(s.DestPool)),
		VkLinks:       s.VKLinks,
	}
}

// fromWire keeps the ports the head already runs on when the panel leaves them
// at zero: a form that forgets a field must not move the fleet onto port 0.
func fromWire(w *headpb.FleetSettings, cur fleet.Settings) fleet.Settings {
	out := fleet.Settings{
		XrayVersion: w.GetXray().GetVersion(),
		XrayURL:     w.GetXray().GetUrl(),
		XraySHA512:  w.GetXray().GetSha512(),
		VKTPVersion: w.GetVktp().GetVersion(),
		VKTPURL:     w.GetVktp().GetUrl(),
		VKTPSHA512:  w.GetVktp().GetSha512(),
		AutoUpgrade: w.GetAutoUpgrade(),
		RealityDest: strings.TrimSpace(w.GetRealityDest()),
		AutoDest:    w.GetAutoDest(),
		PostQuantum: w.GetPostQuantum(),
		TCPPort:     w.GetTcpPort(),
		XHTTPPort:   w.GetXhttpPort(),
		VKLinks:     normalizeVKLinks(w.GetVkLinks()),
	}
	// Пустой dest при включённом автовыборе означает "решай сам", а не "сотри
	// текущий": панель прячет это поле, когда автовыбор включён, и обнулять по
	// её молчанию значит оставить флот без цели для хендшейка до следующей
	// проверки пула
	if out.RealityDest == "" && out.AutoDest {
		out.RealityDest = cur.RealityDest
		out.DestPool = cur.DestPool
	}
	if out.TCPPort == 0 {
		out.TCPPort = cur.TCPPort
	}
	if out.XHTTPPort == 0 {
		out.XHTTPPort = cur.XHTTPPort
	}
	return out
}

// SetNodeBudget changes what a donor pledged for the month.
//
// The head does not check who is asking: the panel already knows whose node it
// is, and the donor-facing API here has no way to name somebody else's node
// anyway. What it does check is zero - a node with no budget cannot be
// scheduled, and accepting it would look like a node that just stopped working.
func (s *Server) SetNodeBudget(_ context.Context, req *headpb.SetNodeBudgetRequest) (*headpb.SetNodeBudgetResponse, error) {
	id := strings.TrimSpace(req.GetNodeId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "missing node id")
	}
	if req.GetDeclaredBudgetBytes() == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"a zero budget is not a budget: nobody can be handed such a node")
	}
	if err := s.reg.SetBudget(id, req.GetDeclaredBudgetBytes()); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	node, err := s.reg.Get(id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &headpb.SetNodeBudgetResponse{
		DeclaredBudgetBytes: node.DeclaredBudgetBytes,
		UsedBytes:           node.UsedBytes,
	}, nil
}
