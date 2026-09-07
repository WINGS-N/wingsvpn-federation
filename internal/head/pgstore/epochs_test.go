package pgstore

import (
	"testing"
	"time"
)

func epochRow(number uint64) EpochRow {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(number) * 24 * time.Hour)
	return EpochRow{
		Number:     number,
		StartAt:    start,
		EndAt:      start.Add(24 * time.Hour),
		Root:       []byte("00000000000000000000000000000000"),
		TotalMicro: 3_000_000,
	}
}

// Листья обязаны пережить рестарт башки: корень в цепочке без них это мёртвый
// груз, по которому донор нихуя не склеймит
func TestEpochSurvivesWithItsLeaves(t *testing.T) {
	db := testDB(t)
	store := NewEpochStore(db.Gorm())
	if err := db.Gorm().AutoMigrate(&EpochRow{}, &EpochLeafRow{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Gorm().Where("number >= ?", 900).Delete(&EpochLeafRow{})
		db.Gorm().Where("number >= ?", 900).Delete(&EpochRow{})
	})

	row := epochRow(900)
	leaves := []EpochLeafRow{
		{Number: 900, Address: "So11111111111111111111111111111111111111112", DonorID: "admin-1", AmountMicro: 1_000_000},
		{Number: 900, Address: "SysvarRent111111111111111111111111111111111", DonorID: "admin-2", AmountMicro: 2_000_000},
	}
	if err := store.Save(row, leaves); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(900)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalMicro != 3_000_000 {
		t.Fatalf("сумма эпохи %d, а клали 3 USDT", got.TotalMicro)
	}
	back, err := store.Leaves(900)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back[0].Address >= back[1].Address {
		t.Fatalf("листья вернулись не те или не по порядку: %+v", back)
	}
}

// Пересчёт эпохи не должен оставлять хвост от прошлой попытки, иначе донор
// склеймит и по старому листу, и по новому
func TestSavingEpochTwiceReplacesLeaves(t *testing.T) {
	db := testDB(t)
	store := NewEpochStore(db.Gorm())
	if err := db.Gorm().AutoMigrate(&EpochRow{}, &EpochLeafRow{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Gorm().Where("number >= ?", 900).Delete(&EpochLeafRow{})
		db.Gorm().Where("number >= ?", 900).Delete(&EpochRow{})
	})

	row := epochRow(901)
	if err := store.Save(row, []EpochLeafRow{
		{Number: 901, Address: "So11111111111111111111111111111111111111112", DonorID: "admin-1", AmountMicro: 5_000_000},
		{Number: 901, Address: "SysvarRent111111111111111111111111111111111", DonorID: "admin-2", AmountMicro: 5_000_000},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(row, []EpochLeafRow{
		{Number: 901, Address: "So11111111111111111111111111111111111111112", DonorID: "admin-1", AmountMicro: 1_000_000},
	}); err != nil {
		t.Fatal(err)
	}
	back, err := store.Leaves(901)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 || back[0].AmountMicro != 1_000_000 {
		t.Fatalf("от прошлого расчёта остался хвост: %+v", back)
	}
}

// Отметка о публикации и выписка донора - то, ради чего всё это и хранится
func TestPublishMarkAndDonorStatement(t *testing.T) {
	db := testDB(t)
	store := NewEpochStore(db.Gorm())
	if err := db.Gorm().AutoMigrate(&EpochRow{}, &EpochLeafRow{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Gorm().Where("number >= ?", 900).Delete(&EpochLeafRow{})
		db.Gorm().Where("number >= ?", 900).Delete(&EpochRow{})
	})

	for _, number := range []uint64{902, 903} {
		if err := store.Save(epochRow(number), []EpochLeafRow{
			{Number: number, Address: "So11111111111111111111111111111111111111112", DonorID: "admin-1", AmountMicro: int64(number)},
		}); err != nil {
			t.Fatal(err)
		}
	}

	last, err := store.Last()
	if err != nil {
		t.Fatal(err)
	}
	if last != 903 {
		t.Fatalf("последняя эпоха %d, а клали до 903", last)
	}

	if err := store.MarkPublished(903, time.Now().UTC(), "5xTxSignature"); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(903)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublishedAt == nil || got.TxRef != "5xTxSignature" {
		t.Fatal("отметка о публикации не сохранилась")
	}
	if err := store.MarkPublished(9999, time.Now().UTC(), "x"); err != ErrNoEpoch {
		t.Fatalf("несуществующая эпоха отметилась опубликованной: %v", err)
	}

	statement, err := store.ForDonor("admin-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(statement) < 2 || statement[0].Number != 903 {
		t.Fatalf("выписка донора не та: %+v", statement)
	}
}

// Выписка и сводка идут сырым SQL с именами таблиц: имя, придуманное из башки,
// разъедется с тем, как gorm их назвал, и запрос просто не найдёт нихуя
func TestStatementAndRecentSpeakTheRealTableNames(t *testing.T) {
	db := testDB(t)
	store := NewEpochStore(db.Gorm())
	if err := db.Gorm().AutoMigrate(&EpochRow{}, &EpochLeafRow{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Gorm().Where("number >= ?", 900).Delete(&EpochLeafRow{})
		db.Gorm().Where("number >= ?", 900).Delete(&EpochRow{})
	})

	for _, number := range []uint64{910, 911} {
		if err := store.Save(epochRow(number), []EpochLeafRow{
			{Number: number, Address: "So11111111111111111111111111111111111111112", DonorID: "admin-1", AmountMicro: 1_000_000},
			{Number: number, Address: "SysvarRent111111111111111111111111111111111", DonorID: "admin-2", AmountMicro: 2_000_000},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.MarkPublished(910, time.Now().UTC(), "5xSig"); err != nil {
		t.Fatal(err)
	}

	statement, err := store.StatementFor("admin-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(statement) != 2 {
		t.Fatalf("в выписке %d строк, а эпох с начислением две", len(statement))
	}
	if statement[0].Number != 911 {
		t.Fatal("выписка идёт не от свежей эпохи")
	}
	// Опубликованная эпоха обязана принести подпись транзакции, иначе донор не
	// поймёт, по чему он вообще может клеймить
	var published int
	for _, row := range statement {
		if row.TxRef != "" && row.PublishedAt != nil {
			published++
		}
		if row.AmountMicro != 1_000_000 {
			t.Fatalf("в выписке чужая сумма %d", row.AmountMicro)
		}
		if len(row.Root) == 0 {
			t.Fatal("корень эпохи не доехал в выписку")
		}
	}
	if published != 1 {
		t.Fatalf("опубликованных эпох в выписке %d, а публиковали одну", published)
	}

	recent, err := store.Recent(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) < 2 {
		t.Fatalf("сводка вернула %d эпох", len(recent))
	}
	if recent[0].Number != 911 || recent[0].Leaves != 2 {
		t.Fatalf("в сводке не та эпоха или не столько листьев: %+v", recent[0])
	}
}
