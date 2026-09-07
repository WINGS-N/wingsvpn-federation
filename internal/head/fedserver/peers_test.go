package fedserver

import (
	"testing"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

type fakeOwners struct {
	owners map[string]string
}

func (f fakeOwners) OwnerOf(key string) (string, bool) {
	id, ok := f.owners[key]
	return id, ok
}

type fakeUsage struct {
	calls []string
}

func (f *fakeUsage) AddUsage(profileID, transport string, up, down uint64) {
	f.calls = append(f.calls, profileID+"|"+transport)
}

// Трафик пира ложится человеку, а чужой пир не приписывается никому: на релее
// живут и собственные клиенты донора, считать их мы не вправе
func TestPeerUsageGoesToTheOwnerOnly(t *testing.T) {
	usage := &fakeUsage{}
	srv := &Server{usage: usage}
	srv.SetPeerOwners(fakeOwners{owners: map[string]string{"wg-ours": "profile-1"}})

	srv.applyPeerUsage([]*fedpb.PeerDeltaSample{
		{PublicKey: "wg-ours", UpDeltaBytes: 100, DownDeltaBytes: 900},
		{PublicKey: "wg-donors-own", UpDeltaBytes: 5000, DownDeltaBytes: 9000},
	})

	if len(usage.calls) != 1 || usage.calls[0] != "profile-1|vktp" {
		t.Fatalf("трафик разнесён не туда: %v", usage.calls)
	}
}

// Без связки ничего не приписываем: молча вешать чужой трафик на людей нельзя
func TestPeerUsageNeedsOwners(t *testing.T) {
	usage := &fakeUsage{}
	srv := &Server{usage: usage}
	srv.applyPeerUsage([]*fedpb.PeerDeltaSample{{PublicKey: "wg-1", UpDeltaBytes: 10}})
	if len(usage.calls) != 0 {
		t.Fatalf("приписали трафик без связки: %v", usage.calls)
	}
}
