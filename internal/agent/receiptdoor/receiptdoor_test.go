package receiptdoor

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func post(t *testing.T, door *Door, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/receipts", strings.NewReader(body))
	door.handle(rec, req)
	return rec
}

// Клиент, которому до панели не достучаться, отдаёт расписку ноде, а та везёт её
// башке своей же сессией
func TestReceiptIsCarried(t *testing.T) {
	door := New()
	signature := base64.StdEncoding.EncodeToString([]byte("подпись"))
	rec := post(t, door, `{"receipts":[{"client_id":"user-1","node_id":"1.2.3.4","transport":"vktp",
		"window_start_unix":100,"window_end_unix":400,"payload_up_bytes":10,"payload_down_bytes":20,
		"nonce":"n1","signature":"`+signature+`"}]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("дверь не приняла: %d", rec.Code)
	}
	carried := door.Drain()
	if len(carried) != 1 || carried[0].GetClientId() != "user-1" || carried[0].GetNonce() != "n1" {
		t.Fatalf("расписка проебалась: %+v", carried)
	}
	if door.Drain() != nil {
		t.Fatal("отдала второй раз")
	}
}

// Мусор без имени и подписи не копим: башке он всё равно не сдался
func TestGarbageIsDropped(t *testing.T) {
	door := New()
	post(t, door, `{"receipts":[{"client_id":"","nonce":"n1","signature":"aaaa"},
		{"client_id":"user-1","nonce":"","signature":"aaaa"},
		{"client_id":"user-1","nonce":"n2","signature":"не base64 нихуя"}]}`)

	if carried := door.Drain(); len(carried) != 0 {
		t.Fatalf("мусор доехал: %+v", carried)
	}
}

// Чужой метод и битое тело дверь отбивает, а не падает
func TestBadRequestsAreRefused(t *testing.T) {
	door := New()
	rec := httptest.NewRecorder()
	door.handle(rec, httptest.NewRequest(http.MethodGet, "/receipts", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET пропустили: %d", rec.Code)
	}
	if got := post(t, door, "{ это не json").Code; got != http.StatusBadRequest {
		t.Fatalf("битое тело пропустили: %d", got)
	}
}

// Сосед по петле не должен ни забить очередь мусором, ни выбить из неё чужие
// честные подписи
func TestFloodDoesNotEvictHonestReceipts(t *testing.T) {
	door := New()
	door.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	signature := base64.StdEncoding.EncodeToString([]byte("подпись"))

	honest := make([]Receipt, 0, maxQueued)
	for i := 0; i < maxQueued; i++ {
		honest = append(honest, Receipt{
			ClientID: "user-1", Nonce: fmt.Sprintf("n%d", i), Signature: signature,
		})
	}
	if got := door.enqueue(honest); got != maxQueued {
		t.Fatalf("честные не влезли: %d", got)
	}
	if got := door.enqueue([]Receipt{{ClientID: "flood", Nonce: "x1", Signature: signature}}); got != 0 {
		t.Fatalf("мусор пролез в полную очередь: %d", got)
	}
	carried := door.Drain()
	if len(carried) != maxQueued || carried[0].GetClientId() != "user-1" {
		t.Fatalf("честные проебались: %d", len(carried))
	}
}

// Одна и та же расписка всеми путями сразу - норма, но копить её по разу на путь
// незачем
func TestRepeatIsSquashed(t *testing.T) {
	door := New()
	door.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	signature := base64.StdEncoding.EncodeToString([]byte("подпись"))
	same := []Receipt{{ClientID: "user-1", Nonce: "n1", Signature: signature}}

	door.enqueue(same)
	if got := door.enqueue(same); got != 0 {
		t.Fatalf("повтор приняли второй раз: %d", got)
	}
	if carried := door.Drain(); len(carried) != 1 {
		t.Fatalf("в очереди не одна штука: %d", len(carried))
	}
}

// Долбить дверь до посинения нельзя: она слушает петлю ноды, куда дотягивается
// любой процесс на машине донора
func TestHammeringIsThrottled(t *testing.T) {
	door := New()
	at := time.Unix(1_700_000_000, 0)
	door.now = func() time.Time { return at }

	for i := 0; i < rateBurst; i++ {
		if !door.allow("10.67.66.5:40000") {
			t.Fatalf("честного зарезали на %d-м запросе", i)
		}
	}
	if door.allow("10.67.66.5:40000") {
		t.Fatal("долбёжку пропустили")
	}
	if !door.allow("10.67.66.9:40000") {
		t.Fatal("зарезали соседа за чужую долбёжку")
	}
	at = at.Add(2 * rateWindow)
	if !door.allow("10.67.66.5:40000") {
		t.Fatal("окно не открылось заново")
	}
}
