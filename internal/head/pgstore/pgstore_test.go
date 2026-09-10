package pgstore

import (
	"context"
	"os"
	"testing"
)

// TestDSN is how these tests find a database. Skipped rather than failed when it
// is unset: the unit suite has to run on a laptop with no Postgres, and a test
// that needs a server is not a reason to redden the whole build.
func testDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("WINGSV_FED_TEST_DSN")
	if dsn == "" {
		t.Skip("set WINGSV_FED_TEST_DSN to run the Postgres tests")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// Applying the schema twice must be a no-op: the head runs AutoMigrate on every
// start, so a migration that is not idempotent would break the second deploy.
func TestSchemaAppliesTwice(t *testing.T) {
	db := testDB(t)
	if err := db.gdb.AutoMigrate(&Node{}, &Allocation{}, &Counter{}, &AbuseSignal{}, &OracleDecision{}); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestTableEmptyReportsBothWays(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if err := db.gdb.Where("1 = 1").Delete(&Node{}).Error; err != nil {
		t.Fatal(err)
	}
	empty, err := db.TableEmpty(&Node{})(ctx)
	if err != nil || !empty {
		t.Fatalf("TableEmpty = %v, %v on a cleared table", empty, err)
	}
	if err := db.gdb.Create(&Node{ID: "probe", Data: []byte(`{}`)}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.gdb.Delete(&Node{}, "id = ?", "probe") })

	empty, err = db.TableEmpty(&Node{})(ctx)
	if err != nil || empty {
		t.Fatalf("TableEmpty = %v, %v with a row present", empty, err)
	}
}

// Seeding must happen once. A table that already holds rows is newer than the
// files by definition, and copying over it would undo everything since the
// switch to Postgres.
func TestSeedSkipsANonEmptyTable(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if err := db.gdb.Create(&Node{ID: "seeded", Data: []byte(`{}`)}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.gdb.Delete(&Node{}, "id = ?", "seeded") })

	copied := false
	err := SeedFromFiles(ctx, Seeder{
		Name:  "nodes",
		Empty: db.TableEmpty(&Node{}),
		Copy:  func() (bool, error) { copied = true; return true, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if copied {
		t.Error("the seeder overwrote a table that already had rows")
	}
}
