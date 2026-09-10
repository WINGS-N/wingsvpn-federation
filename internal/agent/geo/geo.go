// Package geo превращает адреса клиентов в места и сети.
//
// Считает нода, а не башка: адрес - это личность, и наружу уходит только
// расстояние между местами, никогда сами места
package geo

import (
	"math"
	"net/netip"
	"sort"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// clusterKm - радиус одного места. Город берётся вместе со своей областью:
// Питер с Ленобластью и Москва с областью - это один человек, а до дальних
// районов такой области под три сотни километров
const clusterKm = 300

// mobileClusterKm - тот же радиус для сотовых адресов. Они так же держатся
// города и области, но точка нередко стоит в центре региона оператора, поэтому
// допуск шире
const mobileClusterKm = 500

// Point - определённая по адресу точка
type Point struct {
	Lat float64
	Lon float64
}

// Network - чья это сеть. Организация отличает региональные ветки одного
// оператора друг от друга, номер ASN сам по себе этого не даёт
type Network struct {
	ASN uint32
	Org string
	ISP string
	// Mobile - адрес сотового оператора. Место у него такое же городское, но
	// точка может стоять в центре региона, а не там, где человек
	Mobile bool
}

// DB держит открытые базы. Без ASN-базы работает только гео
type DB struct {
	mu   sync.RWMutex
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// Open открывает базы. Отсутствие базы не фатально: гео - один сигнал из
// нескольких
func Open(set Set) (*DB, error) {
	city, err := maxminddb.Open(set.CityPath)
	if err != nil {
		return nil, err
	}
	db := &DB{city: city}
	if set.ASNPath != "" {
		if asn, err := maxminddb.Open(set.ASNPath); err == nil {
			db.asn = asn
		}
	}
	return db, nil
}

// Close отпускает отображённые файлы
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var err error
	if d.city != nil {
		err = d.city.Close()
		d.city = nil
	}
	if d.asn != nil {
		_ = d.asn.Close()
		d.asn = nil
	}
	return err
}

// cityRecord - координаты и код страны. Название города не разбирается: место
// человека логировать нечем, а страна нужна на другое - подписать сервер
type cityRecord struct {
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// asnRecord покрывает обе схемы: у одних баз поля autonomous_system_*, у
// платных - isp и organization
type asnRecord struct {
	Number       uint32 `maxminddb:"autonomous_system_number"`
	Organization string `maxminddb:"autonomous_system_organization"`
	ISP          string `maxminddb:"isp"`
	Org          string `maxminddb:"organization"`
	MCC          string `maxminddb:"mobile_country_code"`
	MNC          string `maxminddb:"mobile_network_code"`
}

// Lookup определяет место по одному адресу
func (d *DB) Lookup(addr string) (Point, bool) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return Point{}, false
	}
	d.mu.RLock()
	reader := d.city
	d.mu.RUnlock()
	if reader == nil {
		return Point{}, false
	}
	var rec cityRecord
	if err := reader.Lookup(ip).Decode(&rec); err != nil {
		return Point{}, false
	}
	if rec.Location.Latitude == 0 && rec.Location.Longitude == 0 {
		return Point{}, false
	}
	return Point{Lat: rec.Location.Latitude, Lon: rec.Location.Longitude}, true
}

// LookupNetwork определяет, чья это сеть
func (d *DB) LookupNetwork(addr string) (Network, bool) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return Network{}, false
	}
	d.mu.RLock()
	reader := d.asn
	d.mu.RUnlock()
	if reader == nil {
		return Network{}, false
	}
	var rec asnRecord
	if err := reader.Lookup(ip).Decode(&rec); err != nil {
		return Network{}, false
	}
	out := Network{ASN: rec.Number, Org: rec.Organization, ISP: rec.ISP, Mobile: rec.MCC != ""}
	if out.Org == "" {
		out.Org = rec.Org
	}
	if out.ISP == "" {
		out.ISP = out.Org
	}
	if out.ASN == 0 && out.Org == "" && out.ISP == "" && !out.Mobile {
		return Network{}, false
	}
	return out, true
}

// DistanceKm - расстояние между точками по дуге большого круга
func DistanceKm(a, b Point) float64 {
	const earthKm = 6371.0
	rad := func(deg float64) float64 { return deg * math.Pi / 180 }
	dLat := rad(b.Lat - a.Lat)
	dLon := rad(b.Lon - a.Lon)
	h := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(a.Lat))*math.Cos(rad(b.Lat))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthKm * math.Asin(math.Min(1, math.Sqrt(h)))
}

// Reading - то, что получает наблюдатель: сколько мест, как далеко самое
// дальнее от первого и сколько за ними разных операторов
type Reading struct {
	Places   int
	MaxKm    float64
	Networks int
}

// Spread меряет каждый адрес относительно первого.
//
// Якорь один и он не двигается: иначе цепочка соседних городов уползает на
// тысячи километров, оставаясь "одним местом"
func (d *DB) Spread(addrs []string) Reading {
	sorted := append([]string(nil), addrs...)
	sort.Strings(sorted)

	var anchor Point
	var anchorMobile, haveAnchor bool
	networks := make(map[string]struct{})
	out := Reading{}
	for _, addr := range sorted {
		net, known := d.LookupNetwork(addr)
		if known {
			networks[networkKey(net)] = struct{}{}
		}
		point, ok := d.Lookup(addr)
		if !ok {
			continue
		}
		if !haveAnchor {
			anchor, anchorMobile, haveAnchor = point, net.Mobile, true
			out.Places = 1
			continue
		}
		limit := float64(clusterKm)
		if net.Mobile || anchorMobile {
			limit = mobileClusterKm
		}
		km := DistanceKm(anchor, point)
		if km <= limit {
			continue
		}
		out.Places++
		if km > out.MaxKm {
			out.MaxKm = km
		}
	}
	out.Networks = len(networks)
	return out
}

// networkKey сводит оператора к одной строке: региональные ветки крупного
// провайдера сидят на разных ASN под одним именем
func networkKey(n Network) string {
	if n.Org != "" {
		return n.Org
	}
	if n.ISP != "" {
		return n.ISP
	}
	return string(rune(n.ASN))
}

// Country отдаёт код страны по адресу, например RU или DE
func (d *DB) Country(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	d.mu.RLock()
	reader := d.city
	d.mu.RUnlock()
	if reader == nil {
		return ""
	}
	var rec cityRecord
	if err := reader.Lookup(ip).Decode(&rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}
