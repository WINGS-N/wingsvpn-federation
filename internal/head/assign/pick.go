package assign

import (
	"math/rand"
	"net"
	"sort"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/registry"
)

// Request is one user's ask
type Request struct {
	// Want is how many nodes to hand out. Two or three: one is a single point of
	// failure, and more than three multiplies the profiles to keep in sync
	Want int
	// Sticky is what the user already has. Reshuffling on every subscription
	// refresh breaks live clients for no gain, so anything still eligible is kept
	Sticky []string
	Rand   *rand.Rand
}

// Candidate is a node that could be handed out, with why
type Candidate struct {
	Node  *registry.Node
	Score Score
}

// Eligible filters the fleet down to what may be handed out at all.
//
// Draining nodes are deliberately excluded: draining means exactly "no new
// users, existing ones keep working"
func Eligible(nodes []*registry.Node, now time.Time, opts Options) []Candidate {
	opts = opts.withDefaults()
	out := make([]Candidate, 0, len(nodes))
	for _, n := range nodes {
		if n.State != fedpb.RotationState_ROTATION_STATE_ACTIVE {
			continue
		}
		// No reachable IPv4, no node. IPv6 is a bonus and never a substitute:
		// most users reach us over v4 only, so a v6-only node is unreachable for
		// almost everybody however good its score
		if ipv4Of(n, now, opts) == nil {
			continue
		}
		score := ScoreNode(n, now, opts)
		if !score.Fresh {
			continue
		}
		out = append(out, Candidate{Node: n, Score: score})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score.Total == out[j].Score.Total {
			return out[i].Node.ID < out[j].Node.ID
		}
		return out[i].Score.Total > out[j].Score.Total
	})
	return out
}

// Pick chooses the nodes a user gets.
//
// Weighted random from the top of the list rather than simply the best: handing
// every new user the highest-scoring node is how one donor ends up carrying the
// federation until it too is exhausted
func Pick(nodes []*registry.Node, now time.Time, opts Options, req Request) []*registry.Node {
	opts = opts.withDefaults()
	if req.Want <= 0 {
		req.Want = 2
	}
	rng := req.Rand
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	pool := Eligible(nodes, now, opts)
	byID := make(map[string]Candidate, len(pool))
	for _, c := range pool {
		byID[c.Node.ID] = c
	}

	var chosen []*registry.Node
	spread := newSpread()
	// Keep what the user already has, while it is still eligible and does not
	// clash with something already kept
	for _, id := range req.Sticky {
		if len(chosen) >= req.Want {
			break
		}
		c, ok := byID[id]
		if !ok || !spread.admits(c.Node, now, opts) {
			continue
		}
		spread.take(c.Node, now, opts)
		chosen = append(chosen, c.Node)
	}

	remaining := make([]Candidate, 0, len(pool))
	for _, c := range pool {
		if spread.chosen[c.Node.ID] {
			continue
		}
		remaining = append(remaining, c)
	}
	if len(remaining) > opts.TopK {
		remaining = remaining[:opts.TopK]
	}

	for len(chosen) < req.Want && len(remaining) > 0 {
		idx := weightedIndex(remaining, rng)
		if idx < 0 {
			break
		}
		c := remaining[idx]
		remaining = append(remaining[:idx], remaining[idx+1:]...)
		if !spread.admits(c.Node, now, opts) {
			continue
		}
		spread.take(c.Node, now, opts)
		chosen = append(chosen, c.Node)
	}
	return chosen
}

// weightedIndex draws one candidate with probability proportional to its score
func weightedIndex(pool []Candidate, rng *rand.Rand) int {
	total := 0.0
	for _, c := range pool {
		total += c.Score.Total
	}
	if total <= 0 {
		// Every remaining node scores zero, so there is nothing to weight by and
		// a uniform draw is the honest answer
		return rng.Intn(len(pool))
	}
	target := rng.Float64() * total
	for i, c := range pool {
		target -= c.Score.Total
		if target <= 0 {
			return i
		}
	}
	return len(pool) - 1
}

// spread enforces that a user's nodes do not share a failure. Two nodes from one
// donor, or one subnet, fail together: a provider suspension, a bad upstream or
// one admin's mistake takes both, which is the whole thing a second node exists
// to survive
type spread struct {
	chosen  map[string]bool
	donors  map[string]bool
	subnets map[string]bool
	// asns is only populated for nodes whose operator declared one. There is no
	// lookup table here, so an undeclared ASN falls back to the /24
	asns map[string]bool
}

func newSpread() *spread {
	return &spread{
		chosen:  map[string]bool{},
		donors:  map[string]bool{},
		subnets: map[string]bool{},
		asns:    map[string]bool{},
	}
}

func (s *spread) admits(n *registry.Node, now time.Time, opts Options) bool {
	if s.chosen[n.ID] {
		return false
	}
	if n.DonorID != "" && s.donors[n.DonorID] {
		return false
	}
	if asn := n.Passport.GetAsn(); asn != "" && s.asns[asn] {
		return false
	}
	if sub := subnetOf(n, now, opts); sub != "" && s.subnets[sub] {
		return false
	}
	return true
}

func (s *spread) take(n *registry.Node, now time.Time, opts Options) {
	s.chosen[n.ID] = true
	if n.DonorID != "" {
		s.donors[n.DonorID] = true
	}
	if asn := n.Passport.GetAsn(); asn != "" {
		s.asns[asn] = true
	}
	if sub := subnetOf(n, now, opts); sub != "" {
		s.subnets[sub] = true
	}
}

// ipv4Of returns the address a client should be pointed at.
//
// A probe-verified address wins outright: the node's own claim proves nothing
// behind NAT, on IPv6-only hosting, or after a provider nulls a route. When no
// probe has ever reached the node the self-reported address is used instead,
// unless the head has been told to require proof - otherwise a federation with
// no vantage point deployed would hand out nothing at all
func ipv4Of(n *registry.Node, now time.Time, opts Options) net.IP {
	for _, addr := range n.VerifiedAddresses(now, opts.ProbeValidFor) {
		if ip := parseV4(addr); ip != nil {
			return ip
		}
	}
	if opts.RequireProbe {
		return nil
	}
	for _, addr := range n.Passport.GetAddresses() {
		if addr.GetIpv6() {
			continue
		}
		if ip := parseV4(addr.GetAddress()); ip != nil {
			return ip
		}
	}
	return nil
}

func parseV4(host string) net.IP {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return ip.To4()
	}
	return nil
}

// subnetOf is the /24 a node sits in: the stand-in for "same rack, same
// provider, same fate" when no ASN was declared
func subnetOf(n *registry.Node, now time.Time, opts Options) string {
	ip := ipv4Of(n, now, opts)
	if ip == nil {
		return ""
	}
	return ip.Mask(net.CIDRMask(24, 32)).String()
}
