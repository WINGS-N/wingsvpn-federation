package intake

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	intakepb "wingsnet.org/federation/gen/intakepb"
	"wingsnet.org/federation/pkg/receipt"
)

type memKeys map[string][]byte

func (m memKeys) Put(subjectID string, key []byte) (bool, error) {
	_, existed := m[subjectID]
	m[subjectID] = key
	return existed, nil
}

func (m memKeys) Get(subjectID string) ([]byte, bool, error) {
	key, ok := m[subjectID]
	return key, ok, nil
}

type memSink struct {
	kept  []*fedpb.TrafficReceipt
	nonce map[string]bool
}

func newSink() *memSink { return &memSink{nonce: map[string]bool{}} }

func (m *memSink) Accept(_ string, r *fedpb.TrafficReceipt) error {
	if m.nonce[r.GetNonce()] {
		return errDuplicate
	}
	m.nonce[r.GetNonce()] = true
	m.kept = append(m.kept, r)
	return nil
}

var errDuplicate = errTest("duplicate")

type errTest string

func (e errTest) Error() string { return string(e) }

func newReceipt(t *testing.T, key ed25519.PrivateKey, subject string, now time.Time, nonce string) *fedpb.TrafficReceipt {
	t.Helper()
	r := &fedpb.TrafficReceipt{
		ClientId: subject, NodeId: "node-1", Transport: receipt.TransportXray,
		WindowStartUnix: now.Add(-5 * time.Minute).Unix(), WindowEndUnix: now.Unix(),
		PayloadUpBytes: 1000, PayloadDownBytes: 9000, Nonce: nonce,
	}
	if err := receipt.Sign(key, r); err != nil {
		t.Fatalf("подпись разъебалась: %v", err)
	}
	return r
}

func setup(t *testing.T, now time.Time) (*Server, ed25519.PrivateKey, *memSink) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := memKeys{"user-1": pub}
	sink := newSink()
	srv := New(keys, sink)
	srv.now = func() time.Time { return now }
	return srv, priv, sink
}

func TestAGoodReceiptIsAccepted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, priv, sink := setup(t, now)
	got, err := srv.SubmitReceipts(context.Background(), &intakepb.SubmitReceiptsRequest{
		SubjectId: "user-1",
		Receipts:  []*fedpb.TrafficReceipt{newReceipt(t, priv, "user-1", now, "n1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAccepted() != 1 || got.GetRejected() != 0 {
		t.Fatalf("честную расписку не приняли: %+v", got)
	}
	if len(sink.kept) != 1 {
		t.Fatal("расписку не сохранили")
	}
}

// Нода не должна уметь выписать расписку за клиента, иначе весь смысл пропал
func TestAForgedSignatureIsRefused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, _, sink := setup(t, now)
	_, otherKey, _ := ed25519.GenerateKey(nil)
	forged := newReceipt(t, otherKey, "user-1", now, "n1")

	got, err := srv.SubmitReceipts(context.Background(), &intakepb.SubmitReceiptsRequest{
		SubjectId: "user-1", Receipts: []*fedpb.TrafficReceipt{forged},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAccepted() != 0 || got.GetRejected() != 1 {
		t.Fatalf("приняли подделку: %+v", got)
	}
	if len(sink.kept) != 0 {
		t.Fatal("подделка легла в базу")
	}
}

// Одна расписка за десяток окон - это десятикратная оплата за один трафик
func TestAReplayIsRefused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, priv, _ := setup(t, now)
	same := newReceipt(t, priv, "user-1", now, "n1")
	req := &intakepb.SubmitReceiptsRequest{
		SubjectId: "user-1", Receipts: []*fedpb.TrafficReceipt{same, same},
	}
	got, err := srv.SubmitReceipts(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetAccepted() != 1 || got.GetRejected() != 1 {
		t.Fatalf("повтор прошёл: %+v", got)
	}
}

func TestAReceiptFromTheFutureIsRefused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, priv, _ := setup(t, now)
	ahead := newReceipt(t, priv, "user-1", now.Add(2*time.Hour), "n1")
	got, _ := srv.SubmitReceipts(context.Background(), &intakepb.SubmitReceiptsRequest{
		SubjectId: "user-1", Receipts: []*fedpb.TrafficReceipt{ahead},
	})
	if got.GetAccepted() != 0 {
		t.Fatalf("расписка из будущего прошла: %+v", got)
	}
}

func TestAncientReceiptsAreRefused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, priv, _ := setup(t, now)
	old := newReceipt(t, priv, "user-1", now.Add(-30*24*time.Hour), "n1")
	got, _ := srv.SubmitReceipts(context.Background(), &intakepb.SubmitReceiptsRequest{
		SubjectId: "user-1", Receipts: []*fedpb.TrafficReceipt{old},
	})
	if got.GetAccepted() != 0 {
		t.Fatalf("месячную давность досыпали задним числом: %+v", got)
	}
}

func TestWithoutAKeyNothingIsAccepted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, priv, _ := setup(t, now)
	_, err := srv.SubmitReceipts(context.Background(), &intakepb.SubmitReceiptsRequest{
		SubjectId: "user-unknown",
		Receipts:  []*fedpb.TrafficReceipt{newReceipt(t, priv, "user-unknown", now, "n1")},
	})
	if err == nil {
		t.Fatal("расписки без зарегистрированного ключа прошли")
	}
}

func TestKeyRotationIsReported(t *testing.T) {
	srv, _, _ := setup(t, time.Unix(1_700_000_000, 0))
	pub, _, _ := ed25519.GenerateKey(nil)
	got, err := srv.RegisterKey(context.Background(), &intakepb.RegisterKeyRequest{
		SubjectId: "user-1", PublicKey: pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.GetChanged() {
		t.Fatal("смену ключа не заметили, а это либо новый телефон, либо чужой")
	}
}

type fakeLedger struct {
	used  map[string]uint64
	users []string
}

func (f *fakeLedger) Usage(subjectID string) uint64 { return f.used[subjectID] }
func (f *fakeLedger) Users() []string               { return f.users }

type fakeSigned struct {
	last map[string]time.Time
	// noKey - у кого ключа нет вовсе. Умолчание обратное: почти во всех тестах
	// ключ есть, иначе обвинение не выписывается в принципе
	noKey map[string]bool
}

func (f *fakeSigned) SignedBytes(string, time.Time) (uint64, error) { return 0, nil }

func (f *fakeSigned) HasKey(subjectID string) (bool, error) { return !f.noKey[subjectID], nil }
func (f *fakeSigned) LastReceiptAt(subjectID string) (time.Time, error) {
	return f.last[subjectID], nil
}

// Трафик идёт, расписок нет - значит либо клиент чужой, либо ему есть что
// прятать от сверки
func TestTrafficWithoutReceiptsIsAccused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := &fakeLedger{used: map[string]uint64{"user-1": 500 << 20}, users: []string{"user-1"}}
	var got []*fedpb.AbuseSignal
	r := NewReconciler(ledger, &fakeSigned{last: map[string]time.Time{}}, func(s *fedpb.AbuseSignal, _ string) {
		got = append(got, s)
	}, nil)
	r.now = func() time.Time { return now }

	r.Once()
	if len(got) != 0 {
		t.Fatalf("обвинили на первом же круге, не зная предыстории: %+v", got)
	}
	ledger.used["user-1"] = 900 << 20
	r.Once()
	if len(got) != 1 || got[0].GetKind() != fedpb.AbuseKind_ABUSE_KIND_NO_RECEIPTS {
		t.Fatalf("свежий трафик без расписок пропустили: %+v", got)
	}
}

// Человек с дохлой сетью не должен огрести за то, что расписка задержалась
func TestARecentReceiptBuysSilence(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := &fakeLedger{used: map[string]uint64{"user-1": 0}, users: []string{"user-1"}}
	signed := &fakeSigned{last: map[string]time.Time{"user-1": now.Add(-10 * time.Minute)}}
	var got []*fedpb.AbuseSignal
	r := NewReconciler(ledger, signed, func(s *fedpb.AbuseSignal, _ string) { got = append(got, s) }, nil)
	r.now = func() time.Time { return now }

	r.Once()
	ledger.used["user-1"] = 900 << 20
	r.Once()
	if len(got) != 0 {
		t.Fatalf("обвинили того, кто прислал расписку десять минут назад: %+v", got)
	}
}

// Мелочь ниже порога клиента расписок не порождает, и требовать их глупо
func TestSmallTrafficIsNotExpectedToBeSigned(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := &fakeLedger{used: map[string]uint64{"user-1": 0}, users: []string{"user-1"}}
	var got []*fedpb.AbuseSignal
	r := NewReconciler(ledger, &fakeSigned{last: map[string]time.Time{}}, func(s *fedpb.AbuseSignal, _ string) {
		got = append(got, s)
	}, nil)
	r.now = func() time.Time { return now }

	r.Once()
	ledger.used["user-1"] = 4 << 20
	r.Once()
	if len(got) != 0 {
		t.Fatalf("обвинили за четыре мегабайта: %+v", got)
	}
}

// Ключа нет - подписывать нечем, и обвинять за неподписанный трафик значит
// наказывать человека за то, что у нас самих не доехало
func TestNoKeyNoAccusation(t *testing.T) {
	ledger := &fakeLedger{used: map[string]uint64{"u1": 0}, users: []string{"u1"}}
	signed := &fakeSigned{last: map[string]time.Time{}, noKey: map[string]bool{"u1": true}}
	var accused int
	rec := NewReconciler(ledger, signed, func(*fedpb.AbuseSignal, string) { accused++ }, nil)
	rec.Once()
	ledger.used["u1"] = 400 << 20
	rec.Once()
	if accused != 0 {
		t.Fatalf("обвинили того, кому нечем подписывать: %d", accused)
	}
}

// Расписку на ноду, которой человеку никогда не давали, принимать нельзя: иначе
// любой клиент накручивает чужой ноде объём и подставляет её под self-dealing
func TestReceiptOnForeignNodeIsRefused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, priv, _ := setup(t, now)
	srv.SetGrants(
		func(_, nodeID string, _ time.Time) bool { return nodeID == "mine" },
		func(address string) (string, bool) {
			owner := map[string]string{"node-1": "mine", "node-9": "notmine"}[address]
			return owner, owner != ""
		},
	)
	pub := ed25519.PublicKey(priv.Public().(ed25519.PublicKey))

	own := newReceipt(t, priv, "user-1", now, "a1")
	if err := srv.check("user-1", pub, own, now); err != nil {
		t.Fatalf("свою ноду завернули: %v", err)
	}

	foreign := newReceipt(t, priv, "user-1", now, "a2")
	foreign.NodeId = "node-9"
	if err := receipt.Sign(priv, foreign); err != nil {
		t.Fatalf("подпись разъебалась: %v", err)
	}
	if err := srv.check("user-1", pub, foreign, now); !errors.Is(err, errNotGranted) {
		t.Fatalf("чужую ноду пропустили: %v", err)
	}
}

// Окно в пять минут физически не унесёт терабайты, и подпись этого не делает
// правдой
func TestImpossibleVolumeIsRefused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	srv, priv, _ := setup(t, now)
	pub := ed25519.PublicKey(priv.Public().(ed25519.PublicKey))

	huge := newReceipt(t, priv, "user-1", now, "b1")
	huge.PayloadUpBytes = 1 << 45
	if err := receipt.Sign(priv, huge); err != nil {
		t.Fatalf("подпись разъебалась: %v", err)
	}
	if err := srv.check("user-1", pub, huge, now); !errors.Is(err, errTooFast) {
		t.Fatalf("терабайты за пятиминутку прошли: %v", err)
	}
}
