package headserver

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/upstream"
)

// Купленные подписки заводит владелец площадки, и только он: это его деньги и
// его аккаунт у продавца, а бан за чужие художества прилетит туда же

// UpstreamPool - то, чем владелец рулит из панели
type UpstreamPool interface {
	List() []upstream.Source
	Put(source upstream.Source) error
	Remove(id string) error
	Enable(on bool)
	Enabled() bool
}

// SetUpstreams включает управление купленными подписками
func (s *Server) SetUpstreams(pool UpstreamPool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreams = pool
}

func (s *Server) upstreamsOrErr() (UpstreamPool, error) {
	s.mu.Lock()
	pool := s.upstreams
	s.mu.Unlock()
	if pool == nil {
		return nil, status.Error(codes.Unimplemented, "this head serves no bought subscriptions")
	}
	return pool, nil
}

// Upstreams отдаёт то, что заведено
func (s *Server) Upstreams(_ context.Context, _ *headpb.UpstreamsRequest) (*headpb.UpstreamsResponse, error) {
	pool, err := s.upstreamsOrErr()
	if err != nil {
		return nil, err
	}
	return upstreamsView(pool), nil
}

// PutUpstream заводит или правит источник
func (s *Server) PutUpstream(_ context.Context, req *headpb.PutUpstreamRequest) (*headpb.UpstreamsResponse, error) {
	pool, err := s.upstreamsOrErr()
	if err != nil {
		return nil, err
	}
	source := req.GetSource()
	if strings.TrimSpace(source.GetId()) == "" || strings.TrimSpace(source.GetUrl()) == "" {
		return nil, status.Error(codes.InvalidArgument, "a source needs an id and a url")
	}
	if err := pool.Put(upstream.Source{
		ID:         strings.TrimSpace(source.GetId()),
		Vendor:     strings.TrimSpace(source.GetVendor()),
		URL:        strings.TrimSpace(source.GetUrl()),
		DeviceID:   strings.TrimSpace(source.GetDeviceId()),
		MaxClients: int(source.GetMaxClients()),
		Enabled:    source.GetEnabled(),
	}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return upstreamsView(pool), nil
}

// RemoveUpstream убирает источник целиком
func (s *Server) RemoveUpstream(_ context.Context, req *headpb.RemoveUpstreamRequest) (*headpb.UpstreamsResponse, error) {
	pool, err := s.upstreamsOrErr()
	if err != nil {
		return nil, err
	}
	if err := pool.Remove(strings.TrimSpace(req.GetId())); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return upstreamsView(pool), nil
}

// EnableUpstreams дёргает общий рубильник
func (s *Server) EnableUpstreams(_ context.Context, req *headpb.EnableUpstreamsRequest) (*headpb.UpstreamsResponse, error) {
	pool, err := s.upstreamsOrErr()
	if err != nil {
		return nil, err
	}
	pool.Enable(req.GetEnabled())
	return upstreamsView(pool), nil
}

func upstreamsView(pool UpstreamPool) *headpb.UpstreamsResponse {
	out := &headpb.UpstreamsResponse{
		Enabled:       pool.Enabled(),
		MinConfidence: upstream.MinConfidence,
	}
	for _, source := range pool.List() {
		view := &headpb.UpstreamSource{
			Id: source.ID, Vendor: source.Vendor, Url: source.URL,
			DeviceId: source.DeviceID, MaxClients: uint32(source.MaxClients),
			Enabled: source.Enabled, Links: uint32(len(source.Links)),
			LastError: source.LastError,
		}
		if !source.FetchedAt.IsZero() {
			view.FetchedUnix = source.FetchedAt.Unix()
		}
		out.Sources = append(out.Sources, view)
	}
	return out
}
