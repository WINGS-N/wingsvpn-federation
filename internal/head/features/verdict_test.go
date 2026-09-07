package features

import (
	"fmt"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Один телефон гоняет через туннель все свои приложения, но почти все они ходят
// системным стеком: обвинять за пару отпечатков значит выебать невиновного
func TestOnePhoneIsNotAccusedOfSpread(t *testing.T) {
	prints := []PrintHit{
		{JA4: "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", Count: 400},
		{JA4: "t13d1312h2_cccccccccccc_dddddddddddd", Count: 30},
		{JA4: "t12d0909h1_eeeeeeeeeeee_ffffffffffff", Count: 5},
	}
	v := BuildWithPrints("user-1", time.Hour, ordinarySightings(), nil, prints)
	for _, f := range Judge(v) {
		if f.Kind == fedpb.AbuseKind_ABUSE_KIND_CLIENT_SPREAD {
			t.Fatalf("обычный телефон обвинён в расшаренном профиле: %s", f.Why)
		}
	}
}

// А вот дюжина стеков ровными долями это уже не одно устройство
func TestManyEvenPrintsLookLikeSharedProfile(t *testing.T) {
	prints := make([]PrintHit, 0, 12)
	for i := 0; i < 12; i++ {
		prints = append(prints, PrintHit{JA4: fmt.Sprintf("t13d15%02dh2_%012d_x", i, i), Count: 20})
	}
	v := BuildWithPrints("user-2", time.Hour, ordinarySightings(), nil, prints)
	if v.DistinctPrints != 12 {
		t.Fatalf("отпечатков насчитали %d, а их дюжина", v.DistinctPrints)
	}
	var found bool
	for _, f := range Judge(v) {
		if f.Kind == fedpb.AbuseKind_ABUSE_KIND_CLIENT_SPREAD {
			found = true
		}
	}
	if !found {
		t.Fatal("дюжина ровных стеков не вызвала ни одного обвинения")
	}
}

// ordinarySightings - обычный фон, чтобы вектор дожил до порога по числу обращений
func ordinarySightings() []Sighting {
	at := time.Now().UTC()
	out := make([]Sighting, 0, 20)
	for i := 0; i < 20; i++ {
		out = append(out, Sighting{
			Domain: fmt.Sprintf("site%02d.example", i), Port: 443, Count: 10,
			UpBytes: 40_000, DownBytes: 400_000, LongLived: 2, At: at,
		})
	}
	return out
}

// Свежие домены пачкой - это фишинг. Но незнание возраста обвинением быть не
// должно: половина зон RDAP не держит вовсе
func TestFreshDomainsAccuseOnlyInBulk(t *testing.T) {
	base := Vector{Requests: 500, Domains: 20}

	// Возраст никому не известен - признак пуст, обвинения нет
	quiet := base
	quiet.AddDomainAges(FreshDomainDays, map[string]float64{})
	for _, f := range Judge(quiet) {
		if f.Why == "почти все домены зарегистрированы на днях" {
			t.Fatal("обвинили за то, что возраст неизвестен")
		}
	}

	// Один свежий среди старых - тоже мимо
	mild := base
	mild.AddDomainAges(FreshDomainDays, map[string]float64{
		"a.example": 3, "b.example": 900, "c.example": 1200, "d.example": 400,
	})
	for _, f := range Judge(mild) {
		if f.Why == "почти все домены зарегистрированы на днях" {
			t.Fatal("обвинили за один свежий домен")
		}
	}

	// Пачка свежих - вот это уже разговор
	bad := base
	ages := map[string]float64{}
	for i := 0; i < 8; i++ {
		ages[string(rune('a'+i))+".example"] = 2
	}
	ages["old.example"] = 3000
	bad.AddDomainAges(FreshDomainDays, ages)
	found := false
	for _, f := range Judge(bad) {
		if f.Why == "почти все домены зарегистрированы на днях" {
			found = true
		}
	}
	if !found {
		t.Fatalf("пачку свежих доменов не заметили: fresh=%d share=%.2f", bad.FreshDomains, bad.FreshDomainShare)
	}
}
