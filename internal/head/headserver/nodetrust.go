package headserver

import (
	"context"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/nodetrust"
	"wingsnet.org/federation/internal/head/registry"
)

// NodeTrust - судья по нодам
type NodeTrust interface {
	Judge(nodeID string) nodetrust.Verdict
	Accused() []nodetrust.Verdict
}

// SetNodeTrust включает раздел доверия к нодам
func (s *Server) SetNodeTrust(j NodeTrust) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeTrust = j
}

// OracleNodes отдаёт доверие к нодам вместе с тем, за что его срезали.
//
// Это репутация для линейки выплат, а не для выдачи: из ротации тёмную ноду
// убирают зонды. Платить по самоотчёту нельзя, а резать выплату тому, чьи цифры
// не сходятся с подписями клиентов, как раз и есть смысл всей затеи
func (s *Server) OracleNodes(_ context.Context, req *headpb.OracleNodesRequest) (*headpb.OracleNodesResponse, error) {
	s.mu.Lock()
	judge := s.nodeTrust
	s.mu.Unlock()
	if judge == nil {
		return nil, status.Error(codes.Unimplemented, "this head does not judge nodes")
	}

	accused := 0
	for _, v := range judge.Accused() {
		if v.Trust < nodetrust.StartingTrust {
			accused++
		}
	}

	nodes := s.reg.List()
	sort.Slice(nodes, func(a, b int) bool { return nodes[a].ID < nodes[b].ID })
	out := &headpb.OracleNodesResponse{Total: uint32(len(nodes)), Accused: uint32(accused)}
	for _, node := range pageOf(nodes, req.GetOffset(), req.GetLimit()) {
		verdict := judge.Judge(node.ID)
		view := &headpb.OracleNode{
			NodeId: node.ID, Trust: int32(verdict.Trust),
			PayoutReduced: verdict.Reduced(), PayoutStopped: verdict.Unpaid(),
			LastSeenUnix: node.LastSeen.Unix(),
		}
		if node.Passport != nil {
			view.Hostname = node.Passport.GetHostname()
		}
		view.DonorId = node.DonorID
		view.ProbeOk, view.ProbeFailed = probeTally(node)
		view.UptimePct = uptimePct(node)
		for reason, weight := range verdict.Reasons {
			view.Reasons = append(view.Reasons, &headpb.OracleNodeReason{
				Reason: string(reason), Weight: weight,
			})
		}
		sort.Slice(view.Reasons, func(a, b int) bool {
			return view.Reasons[a].GetWeight() > view.Reasons[b].GetWeight()
		})
		out.Nodes = append(out.Nodes, view)
	}
	return out, nil
}

// probeTally считает, сколько замеров прошло и сколько обосралось
func probeTally(node *registry.Node) (uint32, uint32) {
	var ok, failed uint32
	for _, m := range node.Reachability {
		if m.OK {
			ok++
			continue
		}
		failed++
	}
	return ok, failed
}

// uptimePct - доля времени, что нода на связи. Считается по последнему
// появлению: без истории точнее не скажешь, а врать точностью тут ни к чему
func uptimePct(node *registry.Node) float64 {
	if node.JoinedAt.IsZero() {
		return 0
	}
	lifetime := time.Since(node.JoinedAt)
	if lifetime <= 0 {
		return 0
	}
	away := time.Since(node.LastSeen)
	if away < 0 {
		away = 0
	}
	up := lifetime - away
	if up < 0 {
		up = 0
	}
	return float64(up) / float64(lifetime) * 100
}
