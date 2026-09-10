package fleet

import (
	"testing"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

type memStore struct {
	data map[string]string
	err  error
}

func (m *memStore) Load() (map[string]string, error) { return m.data, m.err }
func (m *memStore) Save(v map[string]string) error {
	if m.err != nil {
		return m.err
	}
	if m.data == nil {
		m.data = map[string]string{}
	}
	for k, val := range v {
		m.data[k] = val
	}
	return nil
}

// Nodes act on a config only when its version is bigger than the one they hold.
// A version that repeats leaves the whole fleet on the old config for ever.
func TestEveryUpdateRaisesTheConfigVersion(t *testing.T) {
	m, err := New(&memStore{}, Settings{ConfigVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.Update(Settings{XrayVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ConfigVersion != 8 {
		t.Fatalf("ConfigVersion = %d, want 8", first.ConfigVersion)
	}
	second, err := m.Update(Settings{XrayVersion: "v2"})
	if err != nil {
		t.Fatal(err)
	}
	if second.ConfigVersion != 9 {
		t.Errorf("ConfigVersion = %d, want 9", second.ConfigVersion)
	}
}

// Настройки должны пережить перезапуск башки: иначе выбранная версия флота
// молча откатится к тому, что зашито в дефолтах.
func TestSettingsSurviveARestart(t *testing.T) {
	store := &memStore{}
	first, err := New(store, Settings{TCPPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Update(Settings{
		XrayVersion: "v26.7.11-wv", XrayURL: "https://example/x.zip", AutoUpgrade: true, TCPPort: 2053,
	}); err != nil {
		t.Fatal(err)
	}

	again, err := New(store, Settings{TCPPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	got := again.Settings()
	if got.XrayVersion != "v26.7.11-wv" || !got.AutoUpgrade || got.TCPPort != 2053 {
		t.Errorf("после перезапуска = %+v, выбор оператора потерян", got)
	}
	// Версия начинается с единицы, поэтому первое сохранение даёт двойку
	if got.ConfigVersion != 2 {
		t.Errorf("ConfigVersion = %d, want 2", got.ConfigVersion)
	}
}

// Пустой url означает "не трогать": нода должна продолжать нести уже
// установленный бинарь, а не остаться без него.
func TestAnEmptyBuildIsNotPushed(t *testing.T) {
	cfg := Settings{XrayURL: "", VKTPURL: "https://example/v.zip", VKTPVersion: "v2"}.
		Apply(&fedpb.NodeConfig{})
	if cfg.GetXrayBuild() != nil {
		t.Error("пустая сборка Xray всё равно уехала в конфиг")
	}
	if cfg.GetVktpBuild().GetVersion() != "v2" {
		t.Error("заданная сборка VKTP до конфига не доехала")
	}
}

// Нода присылает применённую версию, а новая присылает ноль. Если и у башки
// ноль, то "нода отстала" не выполняется никогда: конфиг собран, сохранён и не
// отправлен ни разу.
func TestVersionNeverStartsAtZero(t *testing.T) {
	m, err := New(&memStore{}, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Settings().ConfigVersion; got == 0 {
		t.Fatal("ConfigVersion = 0: такой конфиг ни одна нода не подхватит")
	}
	cfg := m.Settings().Apply(&fedpb.NodeConfig{})
	if cfg.GetVersion() == 0 {
		t.Error("Apply проставил нулевую версию в конфиг")
	}
}

// Пул целей не должен теряться при обычном сохранении настроек: без него ноды
// снова садятся на один dest, и одно правило у цензора роняет флот целиком.
func TestPoolSurvivesAnUpdate(t *testing.T) {
	store := &memStore{}
	m, err := New(store, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Update(Settings{
		AutoDest: true, RealityDest: "a:443", DestPool: []string{"a:443", "b:443"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := m.Settings().DestPool; len(got) != 2 {
		t.Errorf("пул после сохранения = %v", got)
	}
}

// Пул должен пережить перезапуск башки: иначе после каждого деплоя ноды снова
// сидят на одном dest, пока не отработает следующая проверка пула.
func TestPoolSurvivesARestart(t *testing.T) {
	store := &memStore{}
	first, err := New(store, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Update(Settings{
		AutoDest: true, RealityDest: "a:443", DestPool: []string{"a:443", "b:443", "c:443"},
	}); err != nil {
		t.Fatal(err)
	}

	again, err := New(store, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Settings().DestPool; len(got) != 3 {
		t.Errorf("пул после перезапуска = %v, ожидались три цели", got)
	}
}
