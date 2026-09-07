package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// fakeXray stands in for the binary: it answers the key subcommands and then
// sleeps, which is enough to exercise the whole apply path
func fakeXray(t *testing.T, dir string) {
	t.Helper()
	body := `#!/bin/sh
case "$1" in
x25519) echo "PrivateKey: PRIV-$$"; echo "Password (PublicKey): PUB-$$" ;;
mldsa65) echo "Seed: SEED-$$"; echo "Verify: VERIFY-$$" ;;
*) sleep 30 ;;
esac
`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "xray"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func newSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	fakeXray(t, binDir)
	s := New(Options{
		BinDir:       binDir,
		ConfigDir:    filepath.Join(root, "etc"),
		StateDir:     filepath.Join(root, "state"),
		SkipDownload: true,
	})
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

func config(version uint64) *fedpb.NodeConfig {
	return &fedpb.NodeConfig{
		Version: version,
		Reality: &fedpb.RealityIdentity{Dest: "music.yandex.ru:443", ServerNames: []string{"music.yandex.ru"}},
		Inbounds: []*fedpb.InboundSpec{
			{Tag: "in-tcp", Network: "tcp", Port: 443, Flow: "xtls-rprx-vision", Reality: true},
			{Tag: "in-xhttp", Network: "xhttp", Port: 8443, Reality: true},
		},
	}
}

func TestApplyConfigStartsTheNode(t *testing.T) {
	s := newSupervisor(t)
	effective, err := s.ApplyConfig(context.Background(), config(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(effective) != 2 {
		t.Errorf("effective inbounds = %v, want both", effective)
	}
	if _, err := os.Stat(s.configPath()); err != nil {
		t.Errorf("no config was written: %v", err)
	}
	pub, verify := s.PublicIdentity()
	if pub == "" || verify == "" {
		t.Error("no public identity to report back to the head")
	}
}

// The identity must survive a second push. Regenerating it would hand every
// client already holding the old public key a server that no longer matches
func TestIdentityIsMintedOnce(t *testing.T) {
	s := newSupervisor(t)
	if _, err := s.ApplyConfig(context.Background(), config(1)); err != nil {
		t.Fatal(err)
	}
	first, _ := s.PublicIdentity()

	if _, err := s.ApplyConfig(context.Background(), config(2)); err != nil {
		t.Fatal(err)
	}
	second, _ := s.PublicIdentity()
	if first != second {
		t.Errorf("a second config push regenerated the identity: %q then %q", first, second)
	}
}

// And it must survive the agent restarting, for the same reason
func TestIdentitySurvivesRestart(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	fakeXray(t, binDir)
	opts := Options{
		BinDir:       binDir,
		ConfigDir:    filepath.Join(root, "etc"),
		StateDir:     filepath.Join(root, "state"),
		SkipDownload: true,
	}

	first := New(opts)
	if _, err := first.ApplyConfig(context.Background(), config(1)); err != nil {
		t.Fatal(err)
	}
	before, _ := first.PublicIdentity()
	_ = first.Stop()

	second := New(opts)
	if _, err := second.ApplyConfig(context.Background(), config(1)); err != nil {
		t.Fatal(err)
	}
	after, _ := second.PublicIdentity()
	_ = second.Stop()

	if before != after {
		t.Errorf("the identity changed across a restart: %q then %q", before, after)
	}
}

// The private key is the node's whole inbound identity
func TestKeyFileIsOwnerOnly(t *testing.T) {
	s := newSupervisor(t)
	if _, err := s.ApplyConfig(context.Background(), config(1)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.keyPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// Profiles staged before a config push must land in the rendered config, and one
// user needs a separate entry per inbound because vision cannot be shared
func TestProfilesReachTheConfig(t *testing.T) {
	s := newSupervisor(t)
	err := s.ApplyProfiles(context.Background(), &fedpb.ProfileDelta{Add: []*fedpb.ProfileSpec{
		{ProfileId: "p1", Uuid: "uuid-1", Email: "f-a", Flow: "xtls-rprx-vision", InboundTag: "in-tcp", Metered: true},
		{ProfileId: "p1", Uuid: "uuid-1", Email: "f-a", Flow: "", InboundTag: "in-xhttp", Metered: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyConfig(context.Background(), config(1)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.configPath())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, item := range doc["inbounds"].([]any) {
		in := item.(map[string]any)
		settings, ok := in["settings"].(map[string]any)
		if !ok {
			continue
		}
		clients, ok := settings["clients"].([]any)
		if !ok || len(clients) == 0 {
			continue
		}
		seen[in["tag"].(string)] = clients[0].(map[string]any)["flow"].(string)
	}
	if seen["in-tcp"] != "xtls-rprx-vision" {
		t.Errorf("tcp flow = %q", seen["in-tcp"])
	}
	if flow, ok := seen["in-xhttp"]; !ok || flow != "" {
		t.Errorf("xhttp flow = %q present=%v, want empty", flow, ok)
	}
}

func TestRemoveProfile(t *testing.T) {
	s := newSupervisor(t)
	specs := []*fedpb.ProfileSpec{{ProfileId: "p1", Uuid: "u1", InboundTag: "in-tcp"}}
	if err := s.ApplyProfiles(context.Background(), &fedpb.ProfileDelta{Add: specs}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyProfiles(context.Background(), &fedpb.ProfileDelta{RemoveProfileIds: []string{"p1"}}); err != nil {
		t.Fatal(err)
	}
	if len(s.profiles) != 0 {
		t.Errorf("profiles = %v, want the removal applied", s.profiles)
	}
}

// Parking must actually stop serving, not just record a flag
func TestParkingStopsXray(t *testing.T) {
	s := newSupervisor(t)
	if _, err := s.ApplyConfig(context.Background(), config(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRotationState(fedpb.RotationState_ROTATION_STATE_PARKED); err != nil {
		t.Fatal(err)
	}
	if s.xray.Running() {
		t.Error("a parked node is still serving")
	}
}

// Draining keeps existing clients working: it is a scheduling decision at the
// head, not a local shutdown
func TestDrainingKeepsServing(t *testing.T) {
	s := newSupervisor(t)
	if _, err := s.ApplyConfig(context.Background(), config(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRotationState(fedpb.RotationState_ROTATION_STATE_DRAINING); err != nil {
		t.Fatal(err)
	}
	if !s.xray.Running() {
		t.Error("draining stopped the node instead of just halting new assignments")
	}
}

// A node with no relay must still report honestly rather than claim health
func TestHealthWithoutRelay(t *testing.T) {
	s := newSupervisor(t)
	beat, err := s.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if beat.GetXrayState() != "stopped" {
		t.Errorf("xray state = %q before any config", beat.GetXrayState())
	}
	if _, err := s.ApplyConfig(context.Background(), config(1)); err != nil {
		t.Fatal(err)
	}
	beat, _ = s.Health(context.Background())
	if beat.GetXrayState() != "running" {
		t.Errorf("xray state = %q after apply", beat.GetXrayState())
	}
}

func TestRefusesWithoutBinary(t *testing.T) {
	root := t.TempDir()
	s := New(Options{
		BinDir:       filepath.Join(root, "bin"),
		ConfigDir:    filepath.Join(root, "etc"),
		StateDir:     filepath.Join(root, "state"),
		SkipDownload: true,
	})
	if _, err := s.ApplyConfig(context.Background(), config(1)); err != ErrNoBinary {
		t.Errorf("err = %v, want ErrNoBinary", err)
	}
}

// A profile revoked while the node was unreachable is simply lost, so the head
// re-sends the authoritative set when the node comes back. Anything not in it
// has to go, or the node keeps serving somebody who was moved off it
func TestReplaceDropsWhatTheHeadNoLongerLists(t *testing.T) {
	s := newSupervisor(t)
	ctx := context.Background()
	if err := s.ApplyProfiles(ctx, &fedpb.ProfileDelta{Add: []*fedpb.ProfileSpec{
		{ProfileId: "p1", Uuid: "u1", Email: "f-a", InboundTag: "in-tcp"},
		{ProfileId: "p2", Uuid: "u2", Email: "f-b", InboundTag: "in-tcp"},
	}}); err != nil {
		t.Fatal(err)
	}
	if got := len(s.profiles); got != 2 {
		t.Fatalf("staged %d profiles, want 2", got)
	}

	if err := s.ApplyProfiles(ctx, &fedpb.ProfileDelta{
		Replace: true,
		Add: []*fedpb.ProfileSpec{
			{ProfileId: "p2", Uuid: "u2", Email: "f-b", InboundTag: "in-tcp"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if len(s.profiles) != 1 || s.profiles[0].ID != "p2" {
		t.Errorf("after reconcile: %+v, want only p2", s.profiles)
	}
}

// A reconcile re-sends everything, and adding a user the core already holds is
// an error rather than a no-op
func TestReplaceDoesNotReAddWhatIsAlreadyThere(t *testing.T) {
	s := newSupervisor(t)
	ctx := context.Background()
	spec := []*fedpb.ProfileSpec{{ProfileId: "p1", Uuid: "u1", Email: "f-a", InboundTag: "in-tcp"}}
	if err := s.ApplyProfiles(ctx, &fedpb.ProfileDelta{Add: spec}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyProfiles(ctx, &fedpb.ProfileDelta{Add: spec, Replace: true}); err != nil {
		t.Fatal(err)
	}
	if len(s.profiles) != 1 {
		t.Errorf("profiles = %+v, want the one entry kept once", s.profiles)
	}
}
