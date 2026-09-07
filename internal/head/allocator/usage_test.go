package allocator

import "testing"

// Транспорты не слипаются: у профиля их несколько, человек видит их отдельными
// строками, и одна цифра на двоих врёт ему вдвое
func TestUsageIsKeptPerTransport(t *testing.T) {
	a, _, _ := setup(t, node("n1", 1), node("n2", 2))
	alloc, err := a.Ensure("user-1")
	if err != nil {
		t.Fatalf("выдача обосралась: %v", err)
	}
	var profileID string
	for _, p := range alloc.Profiles {
		profileID = p.ID
		break
	}
	if profileID == "" {
		t.Fatal("профиля не выдали вовсе")
	}

	a.AddUsage(profileID, "tcp", 100, 900)
	a.AddUsage(profileID, "xhttp", 5, 45)
	a.AddUsage(profileID, "tcp", 10, 90)

	rows := a.UsageRows("user-1")
	byTransport := map[string]RowUsage{}
	for _, row := range rows {
		byTransport[row.Transport] = row
	}
	if got := byTransport["tcp"]; got.UpBytes != 110 || got.DownBytes != 990 {
		t.Fatalf("tcp посчитан неверно: %+v", got)
	}
	if got := byTransport["xhttp"]; got.UpBytes != 5 || got.DownBytes != 45 {
		t.Fatalf("xhttp посчитан неверно: %+v", got)
	}
	if a.Usage("user-1") != 1150 {
		t.Fatalf("общий счётчик разошёлся: %d", a.Usage("user-1"))
	}
}
