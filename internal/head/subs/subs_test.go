package subs

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wingsnet.org/federation/internal/head/allocator"
)

func (f *fakeAlloc) Usage(string) uint64 { return f.used }

type fakeAlloc struct {
	used      uint64
	token     string
	userID    string
	links     []string
	err       error
	ensureHit int
	turns     []allocator.TurnProfile
	// lastDevice - кому в последний раз выдавали учётки
	lastDevice string
}

func (f *fakeAlloc) ByToken(token string) (*allocator.Allocation, bool) {
	if token != f.token {
		return nil, false
	}
	return &allocator.Allocation{UserID: f.userID, SubToken: token}, true
}

// Устройство, которому в последний раз выдавали учётки: подписка обязана
// раздавать именно его, а не общие
func (f *fakeAlloc) EnsureDevice(userID, deviceID string) (*allocator.Allocation, error) {
	f.lastDevice = deviceID
	return f.Ensure(userID)
}

func (f *fakeAlloc) Ensure(string) (*allocator.Allocation, error) {
	f.ensureHit++
	return nil, f.err
}

func (f *fakeAlloc) Links(string, string, string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.links, nil
}

func serve(t *testing.T, a Allocations, path string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	NewHandler(a).Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func (f *fakeAlloc) TurnProfiles(string, string) []allocator.TurnProfile { return f.turns }

func TestSubscriptionReturnsTheEncodedLinks(t *testing.T) {
	a := &fakeAlloc{
		token:  "tok-1",
		userID: "user-1",
		links:  []string{"vless://a@1.2.3.4:443?x=1#one", "vless://a@5.6.7.8:8443?x=2#two"},
	}
	rec := serve(t, a, Path+"tok-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	cfg, err := DecodeFrame(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("тело не разбирается как кадр приложения: %v", err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Errorf("Content-Type = %q", ct)
	}
	got := cfg.GetXray().GetProfiles()
	if len(got) != 2 || got[0].GetRawLink() != a.links[0] {
		t.Errorf("профили = %+v", got)
	}
	if rec.Header().Get("Profile-Update-Interval") == "" {
		t.Error("no refresh hint for the client")
	}
	// The body is a bearer credential; a cached copy is a leaked config
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q", cc)
	}
}

// Fetching is the only reliable sign a client is still around, so it also
// refreshes: a user whose node was parked gets a working config from the same
// request that would otherwise hand them a dead one
func TestFetchingRefreshesTheAllocation(t *testing.T) {
	a := &fakeAlloc{token: "tok-1", userID: "user-1", links: []string{"vless://a@1.2.3.4:443#x"}}
	serve(t, a, Path+"tok-1")
	if a.ensureHit != 1 {
		t.Errorf("ensure called %d times, want 1", a.ensureHit)
	}
}

// Telling a guesser apart from a real token would confirm they found a user
func TestAnUnknownTokenIsIndistinguishableFromAMissingOne(t *testing.T) {
	a := &fakeAlloc{token: "tok-1", userID: "user-1"}
	for _, path := range []string{Path + "wrong", Path, Path + "a/b"} {
		rec := serve(t, a, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, rec.Code)
		}
	}
}

// An empty subscription looks to a user like a broken client, so a fleet with
// nothing to give has to say so
func TestNoCapacityIsAnError(t *testing.T) {
	a := &fakeAlloc{token: "tok-1", userID: "user-1", err: errors.New("nope")}
	if rec := serve(t, a, Path+"tok-1"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}

	empty := &fakeAlloc{token: "tok-1", userID: "user-1"}
	if rec := serve(t, empty, Path+"tok-1"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d for an empty link list, want 503", rec.Code)
	}
}

func TestOnlyReadMethodsAreAllowed(t *testing.T) {
	a := &fakeAlloc{token: "tok-1", userID: "user-1", links: []string{"vless://a@1.2.3.4:443#x"}}
	mux := http.NewServeMux()
	NewHandler(a).Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, Path+"tok-1", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

// The installer has to arrive with this head's address already in it: a donor
// pastes one command and should not have to be told a second hostname
func TestInstallerIsServedWithTheHeadBakedIn(t *testing.T) {
	mux := http.NewServeMux()
	RegisterInstaller(mux, "fed.wingsnet.org:9310", "https://example.org/wingsv-fed-linux-__ARCH__")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, InstallerPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "fed.wingsnet.org:9310") {
		t.Error("the served installer does not name the head")
	}
	if strings.Contains(body, "__WINGSV_HEAD__") || strings.Contains(body, "__WINGSV_RELEASE__") {
		t.Error("a placeholder survived into the served script")
	}
	// The script must never be cached: it carries the head it was served by
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}
