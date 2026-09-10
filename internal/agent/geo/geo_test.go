package geo

import "testing"

var (
	moscow      = Point{Lat: 55.75, Lon: 37.62}
	serpukhov   = Point{Lat: 54.92, Lon: 37.41}
	spb         = Point{Lat: 59.94, Lon: 30.31}
	podporozhye = Point{Lat: 60.91, Lon: 34.17}
	novosibirsk = Point{Lat: 55.03, Lon: 82.92}
)

// Область считается вместе со своим городом, другой конец страны - нет
func TestRegionIsOnePlace(t *testing.T) {
	for _, c := range []struct {
		name string
		a, b Point
	}{
		{"Москва и область", moscow, serpukhov},
		{"Питер и Ленобласть", spb, podporozhye},
	} {
		if km := DistanceKm(c.a, c.b); km > clusterKm {
			t.Errorf("%s разъехались на %.0f km при радиусе %d", c.name, km, clusterKm)
		}
	}
	if km := DistanceKm(moscow, novosibirsk); km <= clusterKm {
		t.Errorf("Новосибирск попал в московское место: %.0f km", km)
	}
}

// Москва и Питер - разные места, но переезд между ними обвинением быть не должен
func TestCapitalsAreTwoPlacesButNotAbuse(t *testing.T) {
	km := DistanceKm(moscow, spb)
	if km <= clusterKm {
		t.Fatalf("столицы слились в одно место: %.0f km", km)
	}
	if km >= 700 {
		t.Fatalf("расстояние дотягивает до сигнала: %.0f km", km)
	}
}
