package allocator

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/assign"
	"wingsnet.org/federation/internal/head/registry"
)

var at = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

type pushCall struct {
	nodeID string
	add    int
	remove []string
}

type fakePusher struct {
	calls []pushCall
	fail  map[string]bool
	// peers - какие ключи релея сняли вместе с профилем
	peers []string
	// limits - какие потолки поставили пирам
	limits []*fedpb.PeerLimit
}

func (f *fakePusher) PushProfiles(nodeID string, add []*fedpb.ProfileSpec, remove []string) error {
	if f.fail[nodeID] {
		return errors.New("node refused")
	}
	f.calls = append(f.calls, pushCall{nodeID, len(add), remove})
	return nil
}

func (f *fakePusher) PushProfilesAndPeers(nodeID string, add []*fedpb.ProfileSpec, remove, peers []string) error {
	f.peers = append(f.peers, peers...)
	return f.PushProfiles(nodeID, add, remove)
}

func (f *fakePusher) PushPeerLimits(_ string, limits []*fedpb.PeerLimit) error {
	f.limits = append(f.limits, limits...)
	return nil
}

func testConfig(string) *fedpb.NodeConfig {
	return &fedpb.NodeConfig{
		Version: 1,
		Reality: &fedpb.RealityIdentity{ServerNames: []string{"www.example.com"}, ShortIds: []string{"abcd"}},
		Inbounds: []*fedpb.InboundSpec{
			{Tag: "fed-tcp", Network: "tcp", Port: 443, Flow: "xtls-rprx-vision", Reality: true},
			{Tag: "fed-xhttp", Network: "xhttp", Port: 8443, Reality: true},
		},
	}
}

func node(id string, octet int) *registry.Node {
	return &registry.Node{
		ID:                  id,
		Secret:              "s",
		DonorID:             "donor-" + id,
		DeclaredBudgetBytes: 1 << 40,
		State:               fedpb.RotationState_ROTATION_STATE_ACTIVE,
		PeriodStart:         time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:            at,
		Health:              registry.Health{Uptime: 30 * 24 * 3600, At: at},
		RealityPublicKey:    "PBK-" + id,
		Passport: &fedpb.NodePassport{Addresses: []*fedpb.NodeAddress{
			{Address: fmt.Sprintf("203.0.%d.10", octet)},
		}},
	}
}

func setup(t *testing.T, nodes ...*registry.Node) (*Allocator, *registry.Registry, *fakePusher) {
	t.Helper()
	reg := registry.New()
	reg.SetNow(func() time.Time { return at })
	for _, n := range nodes {
		reg.Add(n)
	}
	push := &fakePusher{fail: map[string]bool{}}
	a := New(reg, push, testConfig, assign.Options{})
	a.now = func() time.Time { return at }
	return a, reg, push
}

// A free user gets more than one node, and the two must not share a fate
func TestUserGetsTwoNodesOnDifferentDonors(t *testing.T) {
	a, _, push := setup(t, node("n1", 1), node("n2", 2), node("n3", 3))
	alloc, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(alloc.Profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(alloc.Profiles))
	}
	donors := map[string]bool{}
	for nodeID := range alloc.Profiles {
		donors["donor-"+nodeID] = true
	}
	if len(donors) != 2 {
		t.Errorf("both nodes came from one donor: %v", alloc.NodeIDs())
	}
	// Each node was told about the profile, as two client entries
	if len(push.calls) != 2 {
		t.Fatalf("pushes = %+v", push.calls)
	}
	for _, c := range push.calls {
		if c.add != 2 {
			t.Errorf("node %s got %d entries, want one per inbound", c.nodeID, c.add)
		}
	}
}

// A client refreshing its subscription must not be moved, or every refresh
// costs the user their live connections
func TestRefreshDoesNotMoveTheUser(t *testing.T) {
	a, _, push := setup(t, node("n1", 1), node("n2", 2), node("n3", 3), node("n4", 4))
	first, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	want := first.NodeIDs()
	pushesAfterFirst := len(push.calls)

	for i := 0; i < 5; i++ {
		again, err := a.Ensure("user-1")
		if err != nil {
			t.Fatal(err)
		}
		if !sameSet(want, again.NodeIDs()) {
			t.Fatalf("refresh %d moved the user %v -> %v", i, want, again.NodeIDs())
		}
	}
	if len(push.calls) != pushesAfterFirst {
		t.Errorf("a refresh reissued profiles: %+v", push.calls[pushesAfterFirst:])
	}
}

// A node that leaves rotation has to be replaced, and must be told to stop
// serving the user - a profile left behind serves somebody nobody is tracking
func TestANodeLeavingRotationIsReplacedAndRevoked(t *testing.T) {
	n1, n2, n3 := node("n1", 1), node("n2", 2), node("n3", 3)
	a, reg, push := setup(t, n1, n2, n3)
	first, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	dropped := first.NodeIDs()[0]
	if err := reg.SetState(dropped, fedpb.RotationState_ROTATION_STATE_PARKED, "budget"); err != nil {
		t.Fatal(err)
	}

	second, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, still := second.Profiles[dropped]; still {
		t.Errorf("the parked node %s is still serving the user", dropped)
	}
	if len(second.Profiles) != 2 {
		t.Errorf("got %d profiles after the replacement, want 2", len(second.Profiles))
	}
	var revoked bool
	for _, c := range push.calls {
		if c.nodeID == dropped && len(c.remove) == 1 {
			revoked = true
		}
	}
	if !revoked {
		t.Errorf("the parked node was never told to drop the profile: %+v", push.calls)
	}
}

// A node that refuses the profile must not be handed to the user anyway: the
// link would point at an account that does not exist
func TestANodeThatRefusesIsNotRecorded(t *testing.T) {
	a, _, push := setup(t, node("n1", 1), node("n2", 2))
	push.fail["n1"] = true
	alloc, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := alloc.Profiles["n1"]; ok {
		t.Error("a node that refused the profile was recorded as serving it")
	}
	if len(alloc.Profiles) != 1 {
		t.Errorf("profiles = %v", alloc.NodeIDs())
	}
}

// An empty fleet must say so rather than hand back an empty subscription, which
// to a user looks like a broken client
func TestNoCapacityIsReported(t *testing.T) {
	a, _, _ := setup(t)
	if _, err := a.Ensure("user-1"); !errors.Is(err, ErrNoCapacity) {
		t.Errorf("err = %v, want ErrNoCapacity", err)
	}
}

// A momentary shortage must not cut off a user who is already served
func TestAServedUserIsKeptWhenTheFleetIsMomentarilyEmpty(t *testing.T) {
	n1, n2 := node("n1", 1), node("n2", 2)
	a, reg, _ := setup(t, n1, n2)
	if _, err := a.Ensure("user-1"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"n1", "n2"} {
		if err := reg.SetState(id, fedpb.RotationState_ROTATION_STATE_DRAINING, "maintenance"); err != nil {
			t.Fatal(err)
		}
	}
	alloc, err := a.Ensure("user-1")
	if err != nil {
		t.Fatalf("a served user was cut off: %v", err)
	}
	if len(alloc.Profiles) != 2 {
		t.Errorf("profiles = %v, want the existing ones kept", alloc.NodeIDs())
	}
}

func TestLinksCoverEveryNodeAndTransport(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2))
	if _, err := a.Ensure("user-1"); err != nil {
		t.Fatal(err)
	}
	links, err := a.Links("user-1", "", "wings-free")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 4 {
		t.Fatalf("got %d links, want two nodes times two transports", len(links))
	}
	for _, l := range links {
		if !strings.HasPrefix(l, "vless://") || !strings.Contains(l, "security=reality") {
			t.Errorf("bad link: %s", l)
		}
	}
}

// Losing allocations on restart would reissue every user a new UUID and break
// every live client at once
func TestAllocationsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	reg := registry.New()
	reg.SetNow(func() time.Time { return at })
	reg.Add(node("n1", 1))
	reg.Add(node("n2", 2))
	push := &fakePusher{fail: map[string]bool{}}

	first, err := Open(reg, push, testConfig, assign.Options{}, NewFileStore(dir+"/alloc.json"))
	if err != nil {
		t.Fatal(err)
	}
	first.now = func() time.Time { return at }
	before, err := first.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}

	second, err := Open(reg, push, testConfig, assign.Options{}, NewFileStore(dir+"/alloc.json"))
	if err != nil {
		t.Fatal(err)
	}
	second.now = func() time.Time { return at }
	after, ok := second.Get("user-1")
	if !ok {
		t.Fatal("the user was forgotten across a restart")
	}
	if !sameSet(before.NodeIDs(), after.NodeIDs()) {
		t.Errorf("nodes changed across a restart: %v -> %v", before.NodeIDs(), after.NodeIDs())
	}
	for nodeID, p := range before.Profiles {
		if after.Profiles[nodeID].UUID != p.UUID {
			t.Errorf("node %s: uuid changed across a restart", nodeID)
		}
	}
}

func TestRevokeTakesTheUserOffEveryNode(t *testing.T) {
	a, _, push := setup(t, node("n1", 1), node("n2", 2))
	alloc, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	nodes := alloc.NodeIDs()
	push.calls = nil
	a.Revoke("user-1")
	if len(push.calls) != len(nodes) {
		t.Fatalf("revoked %d of %d nodes: %+v", len(push.calls), len(nodes), push.calls)
	}
	for _, c := range push.calls {
		if len(c.remove) != 1 || c.add != 0 {
			t.Errorf("revoke on %s sent %+v", c.nodeID, c)
		}
	}
	if _, ok := a.Get("user-1"); ok {
		t.Error("the user is still recorded after a revoke")
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			return false
		}
	}
	return true
}

// The oracle decides how much a user gets and the allocator obeys, or the whole
// scoring apparatus is just talk
func TestTheBandDecidesHowManyNodesAUserGets(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2), node("n3", 3))
	band := 2
	a.SetBandFor(func(string) int { return band })

	full, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Profiles) != 2 {
		t.Fatalf("full band got %d nodes", len(full.Profiles))
	}

	band = 1
	reduced, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(reduced.Profiles) != 1 {
		t.Errorf("reduced band got %d nodes, want one", len(reduced.Profiles))
	}
}

// Quarantine is not "fewer nodes", it is none - and anything the user is still
// holding has to be taken off the nodes serving it
func TestQuarantineTakesEverythingAway(t *testing.T) {
	a, _, push := setup(t, node("n1", 1), node("n2", 2))
	a.SetBandFor(func(string) int { return 2 })
	if _, err := a.Ensure("user-1"); err != nil {
		t.Fatal(err)
	}
	push.calls = nil

	a.SetBandFor(func(string) int { return 0 })
	if _, err := a.Ensure("user-1"); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("err = %v, want ErrQuarantined", err)
	}
	if len(push.calls) != 2 {
		t.Fatalf("revoked on %d nodes, want both: %+v", len(push.calls), push.calls)
	}
	for _, c := range push.calls {
		if len(c.remove) != 1 {
			t.Errorf("node %s was not told to drop the profile: %+v", c.nodeID, c)
		}
	}
	if alloc, ok := a.Get("user-1"); ok && len(alloc.Profiles) != 0 {
		t.Errorf("the user still holds %v", alloc.NodeIDs())
	}
}

// A node only ever reports a profile id, so this is the join that turns it into
// a statement about a person
func TestAProfileResolvesBackToItsUser(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2))
	alloc, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range alloc.Profiles {
		got, ok := a.UserForProfile(p.ID)
		if !ok || got != "user-1" {
			t.Errorf("profile %s resolved to %q (ok=%v)", p.ID, got, ok)
		}
	}
	if _, ok := a.UserForProfile("never-issued"); ok {
		t.Error("an unknown profile resolved to somebody")
	}
}

// Трафик пользователя набегает по дельтам от нод и обнуляется со сменой месяца
func TestUsageAccumulatesAndRollsOver(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2))
	now := at
	a.now = func() time.Time { return now }

	alloc, err := a.Ensure("user-1")
	if err != nil {
		t.Fatal(err)
	}
	var profileID string
	for _, p := range alloc.Profiles {
		profileID = p.ID
		break
	}
	if profileID == "" {
		t.Fatal("профиль не выдан")
	}

	a.AddUsage(profileID, "tcp", 1500, 0)
	a.AddUsage(profileID, "tcp", 500, 0)
	if got := a.Usage("user-1"); got != 2000 {
		t.Fatalf("usage = %d, want 2000", got)
	}

	// Чужой профиль ничего не должен приписать
	a.AddUsage("nobody", "tcp", 10000, 0)
	if got := a.Usage("user-1"); got != 2000 {
		t.Fatalf("после чужой дельты usage = %d, want 2000", got)
	}

	now = time.Date(at.Year(), at.Month()+1, 1, 0, 5, 0, 0, time.UTC)
	a.AddUsage(profileID, "tcp", 300, 0)
	if got := a.Usage("user-1"); got != 300 {
		t.Fatalf("после смены месяца usage = %d, want 300", got)
	}
}

// У каждого устройства своя учётка, иначе лимит устройств бумажный: пересланную
// ссылку на инбаунде от хозяйской нихуя не отличить
func TestEachDeviceGetsItsOwnCredentials(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2))

	phone, err := a.EnsureDevice("user-1", "hwid-phone")
	if err != nil {
		t.Fatal(err)
	}
	laptop, err := a.EnsureDevice("user-1", "hwid-laptop")
	if err != nil {
		t.Fatal(err)
	}
	if phone != laptop {
		t.Fatal("выдача у одного человека должна быть одна на всех")
	}

	phoneProfiles := laptop.ProfilesFor("hwid-phone")
	laptopProfiles := laptop.ProfilesFor("hwid-laptop")
	if len(phoneProfiles) != 2 || len(laptopProfiles) != 2 {
		t.Fatalf("учёток у телефона %d, у ноутбука %d, а нод две", len(phoneProfiles), len(laptopProfiles))
	}
	for nodeID, p := range phoneProfiles {
		other, ok := laptopProfiles[nodeID]
		if !ok {
			t.Fatalf("у ноутбука нет учётки на ноде %s", nodeID)
		}
		if p.UUID == other.UUID || p.ID == other.ID {
			t.Fatal("устройства получили одну и ту же учётку")
		}
		if p.DeviceID != "hwid-phone" || other.DeviceID != "hwid-laptop" {
			t.Fatal("учётка не помнит своё устройство")
		}
	}
}

// Ноды у всех устройств одни и те же: иначе человек видит два разных Germany #1
// и не понимает, какой из них его
func TestDevicesShareTheSameNodesAndNames(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2))
	if _, err := a.EnsureDevice("user-1", "hwid-phone"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.EnsureDevice("user-1", "hwid-laptop"); err != nil {
		t.Fatal(err)
	}

	phoneLinks, err := a.Links("user-1", "hwid-phone", "WINGS V")
	if err != nil {
		t.Fatal(err)
	}
	laptopLinks, err := a.Links("user-1", "hwid-laptop", "WINGS V")
	if err != nil {
		t.Fatal(err)
	}
	if len(phoneLinks) != len(laptopLinks) || len(phoneLinks) == 0 {
		t.Fatalf("ссылок у телефона %d, у ноутбука %d", len(phoneLinks), len(laptopLinks))
	}
	// Имя сервера едет в ссылке после решётки, и оно обязано совпасть
	names := func(links []string) []string {
		out := make([]string, 0, len(links))
		for _, link := range links {
			at := strings.LastIndex(link, "#")
			if at >= 0 {
				out = append(out, link[at+1:])
			}
		}
		sort.Strings(out)
		return out
	}
	phoneNames, laptopNames := names(phoneLinks), names(laptopLinks)
	if len(phoneNames) == 0 || strings.Join(phoneNames, ",") != strings.Join(laptopNames, ",") {
		t.Fatalf("имена серверов разъехались: %v против %v", phoneNames, laptopNames)
	}
	// А вот учётки в ссылках обязаны быть разными
	if strings.Join(phoneLinks, ",") == strings.Join(laptopLinks, ",") {
		t.Fatal("устройства получили одинаковые ссылки")
	}
}

// Клиент, который не назвался, получает общие учётки, а не пустоту
func TestUnnamedDeviceFallsBackToShared(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1))
	if _, err := a.Ensure("user-1"); err != nil {
		t.Fatal(err)
	}
	links, err := a.Links("user-1", "hwid-unknown", "WINGS V")
	if err != nil || len(links) == 0 {
		t.Fatalf("устройство без своих учёток осталось без ссылок: %v", err)
	}
}

// Ушедшая из выдачи нода снимается у ВСЕХ устройств, иначе учётка живёт на
// машине, за которой уже никто не следит
func TestDroppedNodeIsRevokedForEveryDevice(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2), node("n3", 3))
	if _, err := a.EnsureDevice("user-1", "hwid-phone"); err != nil {
		t.Fatal(err)
	}
	alloc, _ := a.Get("user-1")
	gone := alloc.NodeIDs()[0]

	moved := a.DropNode(gone)
	if moved != 1 {
		t.Fatalf("переселено %d человек, а выдача была одна", moved)
	}
	alloc, _ = a.Get("user-1")
	for key := range alloc.Profiles {
		if nodeID, _ := splitKey(key); nodeID == gone {
			t.Fatal("учётка на забранной ноде осталась")
		}
	}
}

// Потолки скорости считает чужой код, и он ходит обратно в аллокатор за
// расходом. Позвать его из-под лока значит встать ждать самого себя - мьютекс
// в go не реентерабельный, и подписка после этого не отвечает уже никому
func TestSpeedHookMayReadTheAllocatorBack(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2))
	a.SetSpeedFor(func(userID string) (uint64, uint64) {
		// Ровно то, что делает Enforcer: спрашивает расход у аллокатора
		_ = a.Usage(userID)
		return 1000, 2000
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := a.Ensure("user-1"); err != nil {
			t.Errorf("Ensure: %v", err)
		}
		if _, err := a.EnsureDevice("user-1", "device-1"); err != nil {
			t.Errorf("EnsureDevice: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("выдача встала на локе: колбэк скорости зовётся из-под него")
	}

	// Лок обязан быть свободен: иначе первый же запрос за подпиской повиснет
	waiting := make(chan struct{})
	go func() {
		defer close(waiting)
		a.Users()
	}()
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("лок остался захваченным после выдачи")
	}
}
