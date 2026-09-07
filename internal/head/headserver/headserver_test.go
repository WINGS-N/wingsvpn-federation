package headserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	fedpb "wingsnet.org/federation/gen/fedpb"
	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/aggregator"
	"wingsnet.org/federation/internal/head/allocator"
	"wingsnet.org/federation/internal/head/profiles"
	"wingsnet.org/federation/internal/head/registry"
	"wingsnet.org/federation/internal/head/tokens"
)

func newServer(t *testing.T) (*Server, *registry.Registry, *aggregator.Aggregator) {
	t.Helper()
	reg := registry.New()
	agg := aggregator.New()
	return New(reg, agg, tokens.New(), "fleet-secret"), reg, agg
}

func addNode(reg *registry.Registry, id, donor string, budget uint64) {
	reg.Add(&registry.Node{
		ID:                  id,
		DonorID:             donor,
		Secret:              "s",
		DeclaredBudgetBytes: budget,
		Passport:            &fedpb.NodePassport{Hostname: id + ".example", Arch: "amd64", AesNi: true},
		State:               fedpb.RotationState_ROTATION_STATE_ACTIVE,
	})
}

// The whole donor story rests on one thing: a donor may never learn who is using
// their machine. That is not "no message mentions a user" - the panel is the
// operator and has to be able to say "give this user nodes". It is that no
// single message ever carries a user and a node together, because that pair is
// the join the entire privacy design exists to keep out of this service.
func TestNoPanelMessageJoinsAUserToANode(t *testing.T) {
	userFields := []string{"user_id", "client_id", "email", "uuid", "subscription_url", "sub_token"}
	nodeFields := []string{"node_id", "hostname", "donor_id", "profile_id"}

	file := headpb.File_headpanel_proto
	messages := file.Messages()
	for i := 0; i < messages.Len(); i++ {
		msg := messages.Get(i)
		users := fieldsMatching(msg, userFields, map[protoreflect.FullName]bool{})
		nodes := fieldsMatching(msg, nodeFields, map[protoreflect.FullName]bool{})
		if len(users) > 0 && len(nodes) > 0 {
			t.Errorf("%s joins a user (%v) to a node (%v)", msg.FullName(), users, nodes)
		}
	}
}

// A profile id would let a donor tie the traffic on their own node back to one
// subscriber. It belongs to the agent contract and has no business here at all.
func TestPanelServiceNeverNamesAProfile(t *testing.T) {
	file := headpb.File_headpanel_proto
	messages := file.Messages()
	for i := 0; i < messages.Len(); i++ {
		msg := messages.Get(i)
		if got := fieldsMatching(msg, []string{"profile"}, map[protoreflect.FullName]bool{}); len(got) > 0 {
			t.Errorf("%s names a profile: %v", msg.FullName(), got)
		}
	}
}

func fieldsMatching(msg protoreflect.MessageDescriptor, needles []string, seen map[protoreflect.FullName]bool) []string {
	if seen[msg.FullName()] {
		return nil
	}
	seen[msg.FullName()] = true
	var out []string
	fields := msg.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		for _, needle := range needles {
			if strings.Contains(string(f.Name()), needle) {
				out = append(out, string(f.Name()))
				break
			}
		}
		if f.Kind() == protoreflect.MessageKind {
			out = append(out, fieldsMatching(f.Message(), needles, seen)...)
		}
	}
	return out
}

func TestPublicCountersCarryNoIdentifiers(t *testing.T) {
	srv, reg, agg := newServer(t)
	addNode(reg, "n1", "d1", 1<<40)
	now := time.Now()
	agg.Ingest(aggregator.Sample{NodeID: "n1", DonorID: "d1", BootID: "b", At: now})
	agg.Ingest(aggregator.Sample{NodeID: "n1", DonorID: "d1", BootID: "b", UpBytes: 100, DownBytes: 200, ActiveSessions: 4, At: now.Add(time.Second)})

	got, err := srv.GetPublicCounters(context.Background(), &headpb.PublicCountersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetNodesOnline() != 1 || got.GetUsersOnline() != 4 {
		t.Errorf("counters = %+v", got)
	}
	if got.GetDonatedBytesThisPeriod() != 300 {
		t.Errorf("donated = %d, want 300", got.GetDonatedBytesThisPeriod())
	}
}

func TestDonorSummaryStaysWithinTheDonor(t *testing.T) {
	srv, reg, agg := newServer(t)
	addNode(reg, "n1", "d1", 1000)
	addNode(reg, "n2", "d2", 5000)
	now := time.Now()
	agg.Ingest(aggregator.Sample{NodeID: "n1", DonorID: "d1", BootID: "b", At: now})
	agg.Ingest(aggregator.Sample{NodeID: "n1", DonorID: "d1", BootID: "b", UpBytes: 10, At: now.Add(time.Second)})
	agg.Ingest(aggregator.Sample{NodeID: "n2", DonorID: "d2", BootID: "b", At: now})
	agg.Ingest(aggregator.Sample{NodeID: "n2", DonorID: "d2", BootID: "b", UpBytes: 999, At: now.Add(time.Second)})

	got, err := srv.DonorSummary(context.Background(), &headpb.DonorSummaryRequest{DonorId: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetNodes() != 1 || got.GetUpBytes() != 10 {
		t.Errorf("summary = %+v, want only d1's own node", got)
	}
	if got.GetDeclaredBudgetBytes() != 1000 {
		t.Errorf("budget = %d, want 1000", got.GetDeclaredBudgetBytes())
	}
	if _, err := srv.DonorSummary(context.Background(), &headpb.DonorSummaryRequest{}); err == nil {
		t.Error("an empty donor id was accepted, which would summarise the fleet")
	}
}

func TestListNodesFiltersByDonor(t *testing.T) {
	srv, reg, _ := newServer(t)
	addNode(reg, "n1", "d1", 1)
	addNode(reg, "n2", "d2", 1)

	all, err := srv.ListNodes(context.Background(), &headpb.ListNodesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.GetNodes()) != 2 {
		t.Errorf("fleet view returned %d nodes", len(all.GetNodes()))
	}
	mine, err := srv.ListNodes(context.Background(), &headpb.ListNodesRequest{DonorId: "d2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mine.GetNodes()) != 1 || mine.GetNodes()[0].GetNodeId() != "n2" {
		t.Errorf("donor view = %+v", mine.GetNodes())
	}
}

// The installer needs the fleet secret to key its transport before the node has
// a secret of its own, so the minted value has to be the compound form
func TestMintedTokenIsTheCompoundInstallerValue(t *testing.T) {
	srv, _, _ := newServer(t)
	got, err := srv.MintEnrollToken(context.Background(), &headpb.MintEnrollTokenRequest{DonorId: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	fleet, enroll, err := tokens.SplitCompound(got.GetEnrollToken())
	if err != nil {
		t.Fatal(err)
	}
	if fleet != "fleet-secret" || enroll == "" {
		t.Errorf("compound token split to %q / %q", fleet, enroll)
	}
	if got.GetExpiresUnix() <= time.Now().Unix() {
		t.Error("token expires in the past")
	}
	if _, err := srv.MintEnrollToken(context.Background(), &headpb.MintEnrollTokenRequest{}); err == nil {
		t.Error("a token was minted without a donor")
	}
}

func TestSetNodeStateRejectsNonsense(t *testing.T) {
	srv, reg, _ := newServer(t)
	addNode(reg, "n1", "d1", 1)
	if _, err := srv.SetNodeState(context.Background(), &headpb.SetNodeStateRequest{
		NodeId: "n1", State: "quarantined", Reason: "abuse",
	}); err != nil {
		t.Fatal(err)
	}
	n, _ := reg.Get("n1")
	if n.State != fedpb.RotationState_ROTATION_STATE_QUARANTINED {
		t.Errorf("state = %v", n.State)
	}
	if _, err := srv.SetNodeState(context.Background(), &headpb.SetNodeStateRequest{
		NodeId: "n1", State: "banished",
	}); err == nil {
		t.Error("an unknown state was accepted")
	}
	if _, err := srv.SetNodeState(context.Background(), &headpb.SetNodeStateRequest{
		NodeId: "nope", State: "active",
	}); err == nil {
		t.Error("an unknown node was accepted")
	}
}

type fakeAllocations struct {
	alloc    *allocator.Allocation
	err      error
	revoked  []string
	entitled int
	used     uint64
	uplink   uint64
	downlink uint64
	users    []string
	rows     []allocator.RowUsage
}

func (f *fakeAllocations) Entitled(string) int { return f.entitled }

func (f *fakeAllocations) Usage(string) uint64 { return f.used }

func (f *fakeAllocations) Speeds(string) (uint64, uint64) { return f.uplink, f.downlink }

func (f *fakeAllocations) Users() []string { return f.users }

func (f *fakeAllocations) UsageRows(string) []allocator.RowUsage { return f.rows }

func (f *fakeAllocations) Ensure(userID string) (*allocator.Allocation, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.alloc, nil
}

func (f *fakeAllocations) Revoke(userID string) { f.revoked = append(f.revoked, userID) }

func TestEnsureUserReturnsASubscriptionUrl(t *testing.T) {
	srv, _, _ := newServer(t)
	srv.SetAllocator(&fakeAllocations{alloc: &allocator.Allocation{
		UserID:      "user-1",
		SubToken:    "tok-abc",
		Profiles:    map[string]profiles.Profile{"n1": {}, "n2": {}},
		StickyUntil: time.Now().Add(time.Hour),
	}}, "https://v.wingsnet.org/")

	got, err := srv.EnsureUser(context.Background(), &headpb.EnsureUserRequest{UserId: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSubscriptionUrl() != "https://v.wingsnet.org/sub/tok-abc" {
		t.Errorf("url = %q", got.GetSubscriptionUrl())
	}
	if got.GetNodes() != 2 {
		t.Errorf("nodes = %d, want 2", got.GetNodes())
	}
	if _, err := srv.EnsureUser(context.Background(), &headpb.EnsureUserRequest{}); err == nil {
		t.Error("an empty user id was accepted")
	}
}

// An empty subscription looks like a broken client, so an exhausted fleet has to
// be an error the panel can show
func TestEnsureUserReportsAnExhaustedFleet(t *testing.T) {
	srv, _, _ := newServer(t)
	srv.SetAllocator(&fakeAllocations{err: allocator.ErrNoCapacity}, "https://v.wingsnet.org")
	_, err := srv.EnsureUser(context.Background(), &headpb.EnsureUserRequest{UserId: "user-1"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", status.Code(err))
	}
}

// A head that serves no free users must say so rather than pretend it worked
func TestUserRpcsRefuseWithoutAnAllocator(t *testing.T) {
	srv, _, _ := newServer(t)
	if _, err := srv.EnsureUser(context.Background(), &headpb.EnsureUserRequest{UserId: "u"}); status.Code(err) != codes.Unimplemented {
		t.Errorf("EnsureUser code = %v", status.Code(err))
	}
	if _, err := srv.RevokeUser(context.Background(), &headpb.RevokeUserRequest{UserId: "u"}); status.Code(err) != codes.Unimplemented {
		t.Errorf("RevokeUser code = %v", status.Code(err))
	}
}

func TestRevokeUserReachesTheAllocator(t *testing.T) {
	srv, _, _ := newServer(t)
	alloc := &fakeAllocations{}
	srv.SetAllocator(alloc, "https://v.wingsnet.org")
	if _, err := srv.RevokeUser(context.Background(), &headpb.RevokeUserRequest{UserId: "user-1"}); err != nil {
		t.Fatal(err)
	}
	if len(alloc.revoked) != 1 || alloc.revoked[0] != "user-1" {
		t.Errorf("revoked = %v", alloc.revoked)
	}
}

// A panel guessing at the installer URL is a panel handing a donor a link to a
// 404, so the head builds the whole command
func TestMintedTokenComesWithAnInstallCommand(t *testing.T) {
	srv, _, _ := newServer(t)
	srv.SetInstaller("https://fed.wingsnet.org/", 750)
	got, err := srv.MintEnrollToken(context.Background(), &headpb.MintEnrollTokenRequest{DonorId: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.GetInstallCommand(), "curl -fsSL https://fed.wingsnet.org/fed/join.sh") {
		t.Errorf("command = %q", got.GetInstallCommand())
	}
	if !strings.Contains(got.GetInstallCommand(), got.GetEnrollToken()) {
		t.Error("the command does not carry the token it was minted with")
	}
	if !strings.HasSuffix(got.GetInstallCommand(), " 750") {
		t.Errorf("command = %q, want the declared donation on the end", got.GetInstallCommand())
	}
}

// A head that serves no installer must not invent a command
func TestNoInstallCommandWithoutAnInstaller(t *testing.T) {
	srv, _, _ := newServer(t)
	got, err := srv.MintEnrollToken(context.Background(), &headpb.MintEnrollTokenRequest{DonorId: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetInstallCommand() != "" {
		t.Errorf("command = %q, want none", got.GetInstallCommand())
	}
}

// Карантин снимает ноды, а не право смотреть на себя. Отказ вместо ответа
// оставлял человека в чёрном ящике: ни доверия, ни трафика, ни причины
func TestQuarantineStillAnswersWithStanding(t *testing.T) {
	srv, _, _ := newServer(t)
	srv.SetAllocator(&fakeAllocations{err: allocator.ErrQuarantined, used: 4096}, "https://v.wingsnet.org")
	got, err := srv.EnsureUser(context.Background(), &headpb.EnsureUserRequest{UserId: "user-1"})
	if err != nil {
		t.Fatalf("err = %v, want an answer", err)
	}
	if !got.GetQuarantined() {
		t.Error("карантин не отмечен: кабинету нечем объяснить пустой список")
	}
	if got.GetNodes() != 0 {
		t.Errorf("nodes = %d, want 0: в карантине ноды сняты", got.GetNodes())
	}
	if got.GetUsedBytes() != 4096 {
		t.Errorf("used = %d, want 4096: трафик человек видеть не перестаёт", got.GetUsedBytes())
	}
}
