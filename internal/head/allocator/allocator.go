// Package allocator owns the join between a free user and the nodes serving
// them.
//
// It lives here and nowhere else on purpose: this is the only place where a user
// and a donated node appear in the same record. Nothing on the donor-facing side
// may read it, which is what makes "a donor sees aggregates only" a structural
// property rather than a promise
package allocator

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/assign"
	"wingsnet.org/federation/internal/head/profiles"
	"wingsnet.org/federation/internal/head/provision"
	"wingsnet.org/federation/internal/head/registry"
)

// Pusher delivers profile changes to a node
type Pusher interface {
	PushProfiles(nodeID string, add []*fedpb.ProfileSpec, remove []string) error
	// PushProfilesAndPeers снимает заодно пиров VK TURN: они живут в релее, и
	// снятие профиля их не трогает
	PushProfilesAndPeers(nodeID string, add []*fedpb.ProfileSpec, remove, peers []string) error
	// PushPeerLimits ставит потолки скорости пирам VK TURN
	PushPeerLimits(nodeID string, limits []*fedpb.PeerLimit) error
}

// DefaultStickyFor is how long a user keeps the same nodes before the pick is
// even reconsidered. Long enough that a client refreshing its subscription is
// never moved mid-session, short enough that a drained node is left behind
const DefaultStickyFor = 24 * time.Hour

// DefaultWant is how many nodes a free user gets. One is a single point of
// failure; more than three multiplies the profiles to keep in step for no gain
const DefaultWant = 2

// Allocation is what one user currently has
type Allocation struct {
	UserID string
	// Profiles is keyed by node id. One profile per node, two client entries per
	// profile
	Profiles map[string]profiles.Profile
	// SubToken is the opaque handle a client fetches its subscription with. It is
	// not derived from the user id: a subscription URL travels through screenshots
	// and chat logs, and must say nothing about who it belongs to
	SubToken    string
	StickyUntil time.Time
	UpdatedAt   time.Time
	// UsedBytes - сколько пронесено за текущий период, PeriodStart - когда он
	// начался. Считается по дельтам от нод, поэтому переживает и снятие профиля,
	// и рестарт ядра на ноде
	UsedBytes   uint64
	PeriodStart time.Time
}

// AddUsage записывает, сколько пронёс профиль. Ищется по profile_id: нода знает
// только его, а кто за ним стоит - дело башки
func (a *Allocator) AddUsage(profileID, transport string, up, down uint64) {
	if up == 0 && down == 0 {
		return
	}
	bytes := up + down
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, alloc := range a.state {
		for key, p := range alloc.Profiles {
			if p.ID != profileID {
				continue
			}
			now := a.now()
			if alloc.PeriodStart.IsZero() {
				alloc.PeriodStart = monthStart(now)
			} else if current := monthStart(now); current.After(alloc.PeriodStart) {
				alloc.PeriodStart = current
				alloc.UsedBytes = 0
			}
			alloc.UsedBytes += bytes
			if p.Usage == nil {
				p.Usage = map[string]profiles.TransportUsage{}
			}
			// Пустой транспорт шлют ноды старой сборки: складываем их в общий
			// ящик, иначе их трафик просто пропадёт из виду
			slot := p.Usage[transport]
			slot.UpBytes += up
			slot.DownBytes += down
			slot.LastSeen = now
			p.Usage[transport] = slot
			alloc.Profiles[key] = p
			a.persistLocked()
			return
		}
	}
}

// Speeds - потолки скорости пользователя, байт в секунду
func (a *Allocator) Speeds(userID string) (uint64, uint64) {
	return a.speedsFor(userID)
}

// Users - кому выдан доступ прямо сейчас
func (a *Allocator) Users() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.state))
	for userID := range a.state {
		out = append(out, userID)
	}
	sort.Strings(out)
	return out
}

// Usage - трафик пользователя за текущий период
func (a *Allocator) Usage(userID string) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if alloc, ok := a.state[userID]; ok {
		return alloc.UsedBytes
	}
	return 0
}

func monthStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}

// NodeIDs lists the nodes serving this user
func (a *Allocation) NodeIDs() []string {
	seen := make(map[string]bool, len(a.Profiles))
	out := make([]string, 0, len(a.Profiles))
	for key := range a.Profiles {
		nodeID, _ := splitKey(key)
		if seen[nodeID] {
			continue
		}
		seen[nodeID] = true
		out = append(out, nodeID)
	}
	return out
}

// Профиль выдаётся НА УСТРОЙСТВО, а не на человека: иначе лимит устройств
// бумажный - ссылку пересылают другу, и на инбаунде его от хозяина уже никак не
// отличить. Набор нод при этом общий, поэтому в приложении список серверов на
// всех устройствах один и тот же, а вот учётка на каждом своя.
//
// Пустое устройство - выдача старого образца и профиль по умолчанию для тех,
// кто скачал подписку, не назвавшись

// keySeparator не встречается ни в идентификаторе ноды (hex), ни в отпечатке
// устройства после нормализации
const keySeparator = "|"

func profileKey(nodeID, deviceID string) string {
	if deviceID == "" {
		return nodeID
	}
	return nodeID + keySeparator + deviceID
}

func splitKey(key string) (nodeID, deviceID string) {
	at := strings.Index(key, keySeparator)
	if at < 0 {
		return key, ""
	}
	return key[:at], key[at+len(keySeparator):]
}

// ProfilesFor отдаёт профили устройства, а если своих у него нет - общие.
//
// Возврат к общим нужен для клиентов, которые устройство не называют: без него
// они остались бы вообще без ссылок
func (a *Allocation) ProfilesFor(deviceID string) map[string]profiles.Profile {
	out := map[string]profiles.Profile{}
	for key, p := range a.Profiles {
		nodeID, device := splitKey(key)
		if device == deviceID {
			out[nodeID] = p
		}
	}
	if len(out) > 0 || deviceID == "" {
		return out
	}
	for key, p := range a.Profiles {
		nodeID, device := splitKey(key)
		if device == "" {
			out[nodeID] = p
		}
	}
	return out
}

// Store persists allocations across a head restart. Losing them would reissue
// every free user a new UUID and break every live client at once
type Store interface {
	Load() (map[string]*Allocation, error)
	Save(map[string]*Allocation) error
}

type nopStore struct{}

func (nopStore) Load() (map[string]*Allocation, error) { return nil, nil }
func (nopStore) Save(map[string]*Allocation) error     { return nil }

// ErrNoCapacity means no node could be handed out. Reported rather than papered
// over with an empty subscription, which looks to a user like a broken client
var ErrNoCapacity = errors.New("allocator: no eligible node")

// ErrQuarantined means the oracle cut this user off. Distinct from having no
// capacity: one is about them, the other is about the fleet
var ErrQuarantined = errors.New("allocator: user is quarantined")

// Allocator hands users nodes and keeps the nodes in step
type Allocator struct {
	reg  *registry.Registry
	push Pusher
	// config is what the head told the fleet to serve. Profiles are rendered
	// against it, so it has to be the same one the nodes applied
	config func(nodeID string) *fedpb.NodeConfig
	opts   assign.Options
	store  Store
	// upstreams - купленные подписки, если владелец их включил
	upstreams Upstreams
	// peers - выданные пиры VK TURN, чтобы карантин снимал и их
	peers Peers

	stickyFor time.Duration
	// grants - журнал выдачи. По нему проверяются расписки, потому что цифрам
	// ноды тут верить нельзя: агент у донора свой
	grants *Grants
	want   int
	now    func() time.Time
	// bandFor is how many nodes a given user is entitled to. Set by the head from
	// the oracle's verdict; nil means everybody gets the default
	bandFor func(userID string) int
	// speedFor - потолки скорости пользователя, байт в секунду. Соразмерны
	// оценке Oracle, а не полосе: полоса это три грубых ступени
	speedFor func(userID string) (uplinkBps, downlinkBps uint64)
	// provisionSecret - из него выводится токен, которым приложение
	// представляется релею на ноде. Пустой означает, что VK TURN не выдаётся
	provisionSecret string

	mu    sync.Mutex
	state map[string]*Allocation
	// byToken indexes subscriptions. Rebuilt on load rather than persisted, so it
	// can never disagree with the allocations themselves
	byToken map[string]string
}

// New builds an allocator over the head's registry
func New(reg *registry.Registry, push Pusher, config func(nodeID string) *fedpb.NodeConfig, opts assign.Options) *Allocator {
	return &Allocator{
		reg:       reg,
		push:      push,
		config:    config,
		opts:      opts,
		store:     nopStore{},
		stickyFor: DefaultStickyFor,
		grants:    NewGrants(),
		want:      DefaultWant,
		now:       time.Now,
		state:     map[string]*Allocation{},
		byToken:   map[string]string{},
	}
}

// Open builds an allocator that survives a restart
func Open(reg *registry.Registry, push Pusher, config func(nodeID string) *fedpb.NodeConfig, opts assign.Options, store Store) (*Allocator, error) {
	a := New(reg, push, config, opts)
	a.store = store
	loaded, err := store.Load()
	if err != nil {
		return nil, err
	}
	if loaded != nil {
		a.state = loaded
		// Журнал выдачи живёт в памяти, поэтому после рестарта его надо
		// восстановить: пустой журнал отбил бы расписки всему флоту разом.
		// Начало берём с запасом на срок приёма, чтобы догоняющие подписи
		// прошли
		since := a.now().Add(-grantMemory)
		for userID, alloc := range loaded {
			if alloc.SubToken != "" {
				a.byToken[alloc.SubToken] = userID
			}
			for _, nodeID := range alloc.NodeIDs() {
				a.grants.Granted(userID, nodeID, since)
			}
		}
	}
	return a, nil
}

// ByToken resolves a subscription handle to what it serves
func (a *Allocator) ByToken(token string) (*Allocation, bool) {
	a.mu.Lock()
	userID, ok := a.byToken[token]
	if !ok {
		a.mu.Unlock()
		return nil, false
	}
	alloc, ok := a.state[userID]
	a.mu.Unlock()
	return alloc, ok
}

// Get returns what a user has without changing anything
func (a *Allocator) Get(userID string) (*Allocation, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	alloc, ok := a.state[userID]
	return alloc, ok
}

// Ensure gives the user a working set of nodes, reusing what they already have.
//
// Reshuffling a user who is already served costs live connections and buys
// nothing, so the existing nodes are kept while they remain eligible and only
// the gaps are filled
func (a *Allocator) Ensure(userID string) (*Allocation, error) {
	// Скорости спрашиваем ДО лока: считает их чужой код, и он ходит обратно в
	// аллокатор за расходом. Под локом это ожидание самого себя навсегда
	up, down := a.speedsFor(userID)

	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	alloc, ok := a.state[userID]
	if !ok {
		token, err := subToken()
		if err != nil {
			return nil, err
		}
		alloc = &Allocation{UserID: userID, Profiles: map[string]profiles.Profile{}, SubToken: token}
		a.state[userID] = alloc
		a.byToken[token] = userID
	}

	want := a.wantFor(userID)
	if want <= 0 {
		// Quarantined: nothing is assigned, and anything held is taken away
		a.revokeLocked(alloc)
		return nil, ErrQuarantined
	}

	current := alloc.NodeIDs()
	if ok && now.Before(alloc.StickyUntil) && len(current) == want && a.allStillServing(current, now) {
		return alloc, nil
	}

	picked := assign.Pick(a.reg.List(), now, a.opts, assign.Request{
		Want:   want,
		Sticky: current,
	})
	if len(picked) == 0 {
		if len(alloc.Profiles) > 0 {
			// Keep what the user has rather than cutting them off because the
			// fleet is momentarily short of capacity
			return alloc, nil
		}
		return nil, ErrNoCapacity
	}

	keep := make(map[string]bool, len(picked))
	for _, n := range picked {
		keep[n.ID] = true
	}
	// Нода ушла из выдачи - снимаем её у ВСЕХ устройств этого человека, иначе
	// профиль остаётся жить на машине, за которой уже никто не следит
	for key, p := range alloc.Profiles {
		nodeID, _ := splitKey(key)
		if keep[nodeID] {
			continue
		}
		delete(alloc.Profiles, key)
		a.grants.Revoked(userID, nodeID, now)
		if err := a.push.PushProfiles(nodeID, nil, []string{p.ID}); err != nil {
			log.Printf("allocator: could not revoke %s on %s: %v", p.ID, nodeID, err)
		}
	}

	for _, n := range picked {
		if _, exists := alloc.Profiles[profileKey(n.ID, "")]; exists {
			continue
		}
		p, err := a.issueLocked(userID, n.ID, "", now, up, down)
		if err != nil {
			return nil, err
		}
		if p == nil {
			continue
		}
		alloc.Profiles[profileKey(n.ID, "")] = *p
		a.grants.Granted(userID, n.ID, now)
	}

	if len(alloc.Profiles) == 0 {
		return nil, ErrNoCapacity
	}
	alloc.StickyUntil = now.Add(a.stickyFor)
	alloc.UpdatedAt = now
	a.persistLocked()
	return alloc, nil
}

// issueLocked выписывает профиль и кладёт его на ноду. Возвращает nil, если
// нода его не приняла: записать такой профиль значит выдать человеку ссылку на
// учётку, которой нет
func (a *Allocator) issueLocked(
	userID, nodeID, deviceID string,
	now time.Time,
	up, down uint64,
) (*profiles.Profile, error) {
	p, err := profiles.Issue(userID, nodeID, now, 0)
	if err != nil {
		return nil, err
	}
	p.DeviceID = deviceID
	p.UplinkBps, p.DownlinkBps = up, down
	// Тот же потолок ставим и пирам релея: без этого VK TURN качал на полной
	// скорости, сколько бы Oracle ни урезал человека
	if limits := a.peerLimits(userID, nodeID, p.ID, p.DownlinkBps); len(limits) > 0 {
		if err := a.push.PushPeerLimits(nodeID, limits); err != nil {
			log.Printf("allocator: peer limits for %s on %s did not reach the node: %v", userID, nodeID, err)
		}
	}
	if err := a.push.PushProfiles(nodeID, p.Specs(a.config(nodeID)), nil); err != nil {
		log.Printf("allocator: could not place a profile on %s: %v", nodeID, err)
		return nil, nil
	}
	return &p, nil
}

// EnsureDevice выдаёт устройству свои учётки на тех же нодах, что и у хозяина.
//
// Ноды общие нарочно: список серверов обязан выглядеть одинаково на телефоне и
// на ноутбуке, иначе человек видит два разных Germany #1 и не понимает, какой
// из них его
func (a *Allocator) EnsureDevice(userID, deviceID string) (*Allocation, error) {
	alloc, err := a.Ensure(userID)
	if err != nil || deviceID == "" {
		return alloc, err
	}

	// Тот же порядок, что и в Ensure: чужой колбэк не должен звучать из-под лока
	up, down := a.speedsFor(userID)

	a.mu.Lock()
	defer a.mu.Unlock()
	alloc, ok := a.state[userID]
	if !ok {
		return nil, ErrNoCapacity
	}
	now := a.now()
	var added bool
	for _, nodeID := range alloc.NodeIDs() {
		key := profileKey(nodeID, deviceID)
		if _, exists := alloc.Profiles[key]; exists {
			continue
		}
		p, err := a.issueLocked(userID, nodeID, deviceID, now, up, down)
		if err != nil {
			return nil, err
		}
		if p == nil {
			continue
		}
		alloc.Profiles[key] = *p
		added = true
	}
	if added {
		alloc.UpdatedAt = now
		a.persistLocked()
	}
	return alloc, nil
}

// UserForProfile resolves a profile id back to the user it was issued to.
//
// A node only ever knows the profile, so this is what turns "this profile is
// being shared" into a statement about a person. It lives here because this is
// the only place the two are joined at all
func (a *Allocator) UserForProfile(profileID string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for userID, alloc := range a.state {
		for _, p := range alloc.Profiles {
			if p.ID == profileID {
				return userID, true
			}
		}
	}
	return "", false
}

// SetBandFor supplies how many nodes a user should get. The oracle decides that;
// the allocator only obeys it
func (a *Allocator) SetBandFor(fn func(userID string) int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bandFor = fn
}

// Entitled - сколько нод полагается пользователю по его полосе доверия
func (a *Allocator) Entitled(userID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.wantFor(userID)
}

// SetSpeedFor supplies the speed caps a user is due
func (a *Allocator) SetSpeedFor(fn func(userID string) (uplinkBps, downlinkBps uint64)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.speedFor = fn
}

func (a *Allocator) speedsFor(userID string) (uint64, uint64) {
	if a.speedFor == nil {
		return 0, 0
	}
	return a.speedFor(userID)
}

func (a *Allocator) wantFor(userID string) int {
	if a.bandFor == nil {
		return a.want
	}
	if got := a.bandFor(userID); got >= 0 {
		return got
	}
	return a.want
}

// SpecsFor is everything a node should be serving right now. It is what a
// reconnecting node is reconciled against, so it has to be derived from the
// stored allocations rather than from anything the node itself claims
func (a *Allocator) SpecsFor(nodeID string) []*fedpb.ProfileSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg := a.config(nodeID)
	var out []*fedpb.ProfileSpec
	for _, alloc := range a.state {
		for key, p := range alloc.Profiles {
			if node, _ := splitKey(key); node != nodeID {
				continue
			}
			out = append(out, p.Specs(cfg)...)
		}
	}
	return out
}

// Revoke takes a user off every node. Used when the oracle quarantines somebody
func (a *Allocator) Revoke(userID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	alloc, ok := a.state[userID]
	if !ok {
		return
	}
	a.revokeLocked(alloc)
	delete(a.state, userID)
	delete(a.byToken, alloc.SubToken)
	a.persistLocked()
}

// revokeLocked takes the user off every node without forgetting them. Callers
// hold the lock
func (a *Allocator) revokeLocked(alloc *Allocation) {
	for key, p := range alloc.Profiles {
		nodeID, _ := splitKey(key)
		// Вместе с учёткой ядра снимаем и пира релея: иначе человек, которого
		// только что отрезали, продолжает ходить через VK TURN
		peers := a.peerKeys(alloc.UserID, nodeID)
		if err := a.push.PushProfilesAndPeers(nodeID, nil, []string{p.ID}, peers); err != nil {
			log.Printf("allocator: could not revoke %s on %s: %v", p.ID, nodeID, err)
		}
		delete(alloc.Profiles, key)
		a.grants.Revoked(alloc.UserID, nodeID, a.now())
	}
}

// subToken is 256 bits of randomness. It is a bearer credential for one user's
// whole config, so it has to be unguessable rather than merely unique
func subToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// countryNumbers нумерует ноды внутри их страны в устойчивом порядке: номер не
// должен меняться от того, кто и когда спросил
func (a *Allocator) countryNumbers() map[string]int {
	byCountry := map[string][]string{}
	for _, node := range a.reg.List() {
		country := strings.ToUpper(node.Passport.GetCountry())
		byCountry[country] = append(byCountry[country], node.ID)
	}
	out := map[string]int{}
	for _, ids := range byCountry {
		sort.Strings(ids)
		for i, id := range ids {
			out[id] = i + 1
		}
	}
	return out
}

// Links renders what the user's client needs
func (a *Allocator) Links(userID, deviceID, label string) ([]string, error) {
	a.mu.Lock()
	alloc, ok := a.state[userID]
	a.mu.Unlock()
	if !ok {
		return nil, ErrNoCapacity
	}
	// Купленные серверы идут тем же списком: для человека это один набор, а не
	// два сорта доступа
	out := a.upstreamLinks(userID)
	// Номер сервера считается внутри страны и по всему флоту, а не по выдаче
	// одного человека: иначе один и тот же сервер у двух людей звался бы
	// по-разному, и жалоба "не works Russia #2" ничего не значила бы
	numbers := a.countryNumbers()

	for nodeID, p := range alloc.ProfilesFor(deviceID) {
		node, err := a.reg.Get(nodeID)
		if err != nil {
			continue
		}
		// Имя считается от ноды, а не от учётки: на всех устройствах человека
		// список серверов обязан выглядеть одинаково
		name := profiles.DisplayName(node.Passport.GetCountry(), numbers[nodeID], "")
		links, err := p.Links(node, a.config(nodeID), name)
		if err != nil {
			// A node that has not reported its identity yet cannot be linked to.
			// Skipping beats emitting a link that silently fails to connect
			log.Printf("allocator: no link for node %s: %v", nodeID, err)
			continue
		}
		out = append(out, links...)
	}
	return out, nil
}

// allStillServing reports whether every node the user has is still active and
// fresh. A parked node in the set means the pick has to be redone
func (a *Allocator) allStillServing(nodeIDs []string, now time.Time) bool {
	if len(nodeIDs) == 0 {
		return false
	}
	for _, id := range nodeIDs {
		n, err := a.reg.Get(id)
		if err != nil {
			return false
		}
		if n.State != fedpb.RotationState_ROTATION_STATE_ACTIVE {
			return false
		}
		if !assign.ScoreNode(n, now, a.opts).Fresh {
			return false
		}
	}
	return true
}

func (a *Allocator) persistLocked() {
	if err := a.store.Save(a.state); err != nil {
		log.Printf("allocator: persist: %v", err)
	}
}

// SetProvisionSecret включает выдачу VK TURN: из секрета выводится токен, по
// которому релей на ноде спрашивает башку, кому минтить пир
func (a *Allocator) SetProvisionSecret(secret string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.provisionSecret = secret
}

// VerifyProvision подтверждает, что этот профиль правда выдан этой ноде
func (a *Allocator) VerifyProvision(clientID string, token []byte, nodeID string) bool {
	a.mu.Lock()
	secret := a.provisionSecret
	var found *profiles.Profile
	for _, alloc := range a.state {
		for key, p := range alloc.Profiles {
			node, _ := splitKey(key)
			if p.ID != clientID {
				continue
			}
			if nodeID != "" && node != nodeID {
				continue
			}
			copied := p
			found = &copied
			break
		}
		if found != nil {
			break
		}
	}
	a.mu.Unlock()
	if secret == "" || found == nil {
		return false
	}
	return provision.Matches(secret, clientID, token)
}

// TurnProfiles - профили VK TURN этого пользователя, по одному на ноду с релеем
func (a *Allocator) TurnProfiles(userID, deviceID string) []TurnProfile {
	a.mu.Lock()
	alloc, ok := a.state[userID]
	secret := a.provisionSecret
	a.mu.Unlock()
	if !ok || secret == "" {
		return nil
	}
	numbers := a.countryNumbers()

	out := make([]TurnProfile, 0, len(alloc.Profiles))
	for nodeID, p := range alloc.ProfilesFor(deviceID) {
		node, err := a.reg.Get(nodeID)
		if err != nil || node.RelayEndpoint == "" {
			continue
		}
		out = append(out, TurnProfile{
			ID:       p.ID,
			Name:     profiles.DisplayName(node.Passport.GetCountry(), numbers[nodeID], "vktp"),
			Endpoint: node.RelayEndpoint,
			ClientID: p.ID,
			Token:    provision.TokenHex(secret, p.ID),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// TurnProfile - то, что нужно приложению, чтобы поднять VK TURN на этой ноде
type TurnProfile struct {
	ID       string
	Name     string
	Endpoint string
	ClientID string
	Token    string
}

// DropNode снимает с ноды всех, кому она была выдана.
//
// Нужен, когда донор забирает машину: иначе люди остаются с профилями, которых
// уже нет, и первая же попытка подключиться выглядит как то, что федерация
// сдохла. Возвращает, скольких пришлось переселить
func (a *Allocator) DropNode(nodeID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	var moved int
	for _, alloc := range a.state {
		var hit bool
		for key := range alloc.Profiles {
			if node, _ := splitKey(key); node == nodeID {
				delete(alloc.Profiles, key)
				hit = true
			}
		}
		if !hit {
			continue
		}
		// Ноду забирают целиком, так что отзывать учётки на ней самой смысла
		// нихуя нет: она уже не наша. Забываем выдачу, и человек получит другую
		// на ближайшем обновлении подписки.
		// Липкость сбрасываем: иначе он будет сутки ждать замены
		alloc.StickyUntil = time.Time{}
		moved++
	}
	if moved > 0 {
		a.persistLocked()
	}
	return moved
}

// HeldNode - была ли эта нода у человека в это окно. По этому башка и решает,
// верить ли расписке: своих цифр нода для такой проверки не даёт
func (a *Allocator) HeldNode(userID, nodeID string, windowEnd time.Time) bool {
	return a.grants.Held(userID, nodeID, windowEnd)
}
