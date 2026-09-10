// Package fleet holds the choices an operator makes for every node at once:
// which builds to carry, whose TLS identity to borrow, and whether nodes may
// upgrade themselves.
//
// It exists because these used to be a flag on the head and a flag on the agent,
// which made changing the fleet's Xray version a redeploy of the head and a visit
// to somebody else's server. They are decisions, not deployment parameters, so
// they live in the database and reach nodes through the config they already get.
package fleet

import (
	"crypto/sha512"
	"encoding/binary"
	"strconv"
	"strings"
	"sync"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Keys in the settings table. Spelled out rather than derived from Go names, so
// a rename in code cannot silently orphan the stored value.
const (
	keyXrayVersion = "xray.version"
	keyXrayURL     = "xray.url"
	keyXraySHA     = "xray.sha512"
	keyVKTPVersion = "vktp.version"
	keyVKTPURL     = "vktp.url"
	keyVKTPSHA     = "vktp.sha512"
	keyAutoUpgrade = "auto_upgrade"
	keyRealityDest = "reality.dest"
	keyAutoDest    = "reality.auto_dest"
	keyPostQuantum = "reality.post_quantum"
	keyTCPPort     = "ports.tcp"
	keyXHTTPPort   = "ports.xhttp"
	keyDestPool    = "reality.dest_pool"
	keyConfigVer   = "config.version"
	// Настройки пути VK TURN. Живут тут, а не в приложении, потому что при
	// изменениях в инфраструктуре звонков чинить это надо сменой значения, а
	// не выкаткой версии и ожиданием, пока все обновятся
	keyVKFingerprint = "vktp.browser_fingerprint"
	keyVKWrapMode    = "vktp.wrap_mode"
	keyVKWrapCipher  = "vktp.wrap_cipher"
	keyVKDNSMode     = "vktp.dns_mode"
	keyVKAuthMode    = "vktp.auth_mode"
	// keyVKLinks - пул ссылок на весь флот. Хранится строкой с переводами
	// строки: без записи он жил только в памяти и пропадал с каждым выкатом
	keyVKLinks = "vktp.links"
)

// Store is where the choices survive a restart
type Store interface {
	Load() (map[string]string, error)
	Save(map[string]string) error
}

// Settings is the operator's current answer for the whole fleet
type Settings struct {
	XrayVersion string
	XrayURL     string
	XraySHA512  string
	VKTPVersion string
	VKTPURL     string
	VKTPSHA512  string
	AutoUpgrade bool
	RealityDest string
	AutoDest    bool
	// PostQuantum включён по умолчанию: подпись ML-DSA-65 поверх REALITY нужна
	// именно там, где трафик пишут сегодня, чтобы расшифровать завтра. Она
	// помещается не в каждый заимствованный хендшейк, поэтому её можно снять -
	// но снимать должен человек, а не умолчание
	PostQuantum bool
	TCPPort     uint32
	XHTTPPort   uint32
	// DestPool is every dest the head verified. Nodes are spread across it by
	// DestFor; RealityDest stays as the answer for a fleet with no pool yet.
	DestPool []string
	// VKTP - что раздаётся выданным профилям VK TURN
	VKFingerprint string
	VKWrapMode    string
	VKWrapCipher  string
	VKDNSMode     string
	VKAuthMode    string
	// VKLinks - пул ссылок на весь флот, который уезжает приложению при провижне.
	// Одна ссылка из QR это один сдохший звонок до полной потери связи, а
	// набирать их руками человек не должен
	VKLinks []string
	// ConfigVersion is what nodes compare against. It only ever goes up: a node
	// that already applied a version needs a bigger number to act again, so
	// reusing one would leave the fleet on the old config for ever.
	ConfigVersion uint64
}

// Manager keeps the settings and stamps them onto the config the fleet serves.
type Manager struct {
	mu    sync.Mutex
	store Store
	cur   Settings
}

// New loads what was stored, falling back to the defaults it is given.
//
// The version starts at one, never zero: a node reports the version it applied,
// and a fresh node reports zero. Leave the head at zero too and "the node is
// behind" is never true - the config is built, stored, and never sent.
func New(store Store, fallback Settings) (*Manager, error) {
	if fallback.ConfigVersion == 0 {
		fallback.ConfigVersion = 1
	}
	m := &Manager{store: store, cur: fallback}
	if store == nil {
		return m, nil
	}
	raw, err := store.Load()
	if err != nil {
		return nil, err
	}
	m.cur = merge(fallback, raw)
	return m, nil
}

// Settings returns the current answer
func (m *Manager) Settings() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// Update applies a change and bumps the config version, so every node picks it
// up on its next hello without anybody restarting anything.
func (m *Manager) Update(next Settings) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next.ConfigVersion = m.cur.ConfigVersion + 1
	if m.store != nil {
		if err := m.store.Save(flatten(next)); err != nil {
			return Settings{}, err
		}
	}
	m.cur = next
	return next, nil
}

// DestFor picks which borrowed identity one node presents.
//
// A single dest across the fleet is a single point of failure: block that one
// host and every node fails at the handshake at the same moment. Spreading the
// pool across nodes means a blocked dest costs the share of nodes that used it,
// not all of them.
//
// The choice is derived from the node id rather than random, so a node keeps its
// dest across restarts - the links already handed out carry it as the SNI, and a
// dest that moved would break every one of them.
func (s Settings) DestFor(nodeID string) string {
	pool := s.DestPool
	if len(pool) == 0 {
		return s.RealityDest
	}
	sum := sha512.Sum512_256([]byte(nodeID))
	return pool[binary.BigEndian.Uint32(sum[:4])%uint32(len(pool))]
}

// Apply writes the fleet's build choices into a rendered config.
func (s Settings) Apply(cfg *fedpb.NodeConfig) *fedpb.NodeConfig {
	if cfg == nil {
		return nil
	}
	cfg.Version = s.ConfigVersion
	cfg.AutoUpgrade = s.AutoUpgrade
	if s.XrayURL != "" {
		cfg.XrayBuild = &fedpb.BinarySpec{Version: s.XrayVersion, Url: s.XrayURL, Sha512: s.XraySHA512}
	}
	if s.VKTPURL != "" {
		cfg.VktpBuild = &fedpb.BinarySpec{Version: s.VKTPVersion, Url: s.VKTPURL, Sha512: s.VKTPSHA512}
	}
	return cfg
}

func merge(base Settings, raw map[string]string) Settings {
	get := func(key, fallback string) string {
		if v, ok := raw[key]; ok {
			return v
		}
		return fallback
	}
	boolOf := func(key string, fallback bool) bool {
		v, ok := raw[key]
		if !ok {
			return fallback
		}
		return v == "1" || strings.EqualFold(v, "true")
	}
	uintOf := func(key string, fallback uint32) uint32 {
		v, ok := raw[key]
		if !ok {
			return fallback
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return fallback
		}
		return uint32(n)
	}
	out := Settings{
		XrayVersion:   get(keyXrayVersion, base.XrayVersion),
		XrayURL:       get(keyXrayURL, base.XrayURL),
		XraySHA512:    get(keyXraySHA, base.XraySHA512),
		VKTPVersion:   get(keyVKTPVersion, base.VKTPVersion),
		VKTPURL:       get(keyVKTPURL, base.VKTPURL),
		VKTPSHA512:    get(keyVKTPSHA, base.VKTPSHA512),
		AutoUpgrade:   boolOf(keyAutoUpgrade, base.AutoUpgrade),
		RealityDest:   get(keyRealityDest, base.RealityDest),
		AutoDest:      boolOf(keyAutoDest, base.AutoDest),
		PostQuantum:   boolOf(keyPostQuantum, base.PostQuantum),
		DestPool:      splitPool(get(keyDestPool, strings.Join(base.DestPool, ","))),
		VKFingerprint: get(keyVKFingerprint, base.VKFingerprint),
		VKWrapMode:    get(keyVKWrapMode, base.VKWrapMode),
		VKWrapCipher:  get(keyVKWrapCipher, base.VKWrapCipher),
		VKDNSMode:     get(keyVKDNSMode, base.VKDNSMode),
		VKAuthMode:    get(keyVKAuthMode, base.VKAuthMode),
		VKLinks:       splitLines(get(keyVKLinks, strings.Join(base.VKLinks, "\n"))),
		TCPPort:       uintOf(keyTCPPort, base.TCPPort),
		XHTTPPort:     uintOf(keyXHTTPPort, base.XHTTPPort),
	}
	if v, ok := raw[keyConfigVer]; ok {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			out.ConfigVersion = n
		}
	}
	if out.ConfigVersion == 0 {
		out.ConfigVersion = base.ConfigVersion
	}
	return out
}

// splitPool parses the stored list. Empty means no pool, not one empty entry -
// a single blank dest would send the whole fleet at nothing.
func splitPool(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitLines разбирает сохранённый пул. Пустая строка - это пустой пул, а не
// одна пустая ссылка: такую приложение приняло бы за рабочую
func splitLines(raw string) []string {
	out := make([]string, 0, 4)
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func flatten(s Settings) map[string]string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	return map[string]string{
		keyXrayVersion:   s.XrayVersion,
		keyXrayURL:       s.XrayURL,
		keyXraySHA:       s.XraySHA512,
		keyVKTPVersion:   s.VKTPVersion,
		keyVKTPURL:       s.VKTPURL,
		keyVKTPSHA:       s.VKTPSHA512,
		keyAutoUpgrade:   b(s.AutoUpgrade),
		keyRealityDest:   s.RealityDest,
		keyAutoDest:      b(s.AutoDest),
		keyPostQuantum:   b(s.PostQuantum),
		keyDestPool:      strings.Join(s.DestPool, ","),
		keyVKFingerprint: s.VKFingerprint,
		keyVKWrapMode:    s.VKWrapMode,
		keyVKWrapCipher:  s.VKWrapCipher,
		keyVKDNSMode:     s.VKDNSMode,
		keyVKAuthMode:    s.VKAuthMode,
		keyVKLinks:       strings.Join(s.VKLinks, "\n"),
		keyTCPPort:       strconv.FormatUint(uint64(s.TCPPort), 10),
		keyXHTTPPort:     strconv.FormatUint(uint64(s.XHTTPPort), 10),
		keyConfigVer:     strconv.FormatUint(s.ConfigVersion, 10),
	}
}
