package geo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxDownload ограничивает размер скачиваемого: городская база около 60 MB, и
// редирект на что-то огромное не должен забить чужой диск
const maxDownload = 400 << 20

// Keys - ключи, которые есть у оператора. Пустые означают бесплатные базы, для
// которых не нужен аккаунт. Берутся из окружения, а не из argv: лицензионный
// ключ в командной строке виден всей машине
type Keys struct {
	// MaxMind по платной подписке отдаёт GeoIP2 - самые точные город и ISP,
	// по бесплатному аккаунту тот же ключ отдаёт GeoLite2
	MaxMind string
	// DBIP - платный ключ db-ip.com: полная городская база вместо Lite плюс ISP
	DBIP string
}

// Set - базы, которые в итоге достались ноде. Отсутствие ASN-базы не ошибка:
// гео здесь один сигнал из нескольких
type Set struct {
	CityPath string
	ASNPath  string
}

// Fetch качает лучшие базы, которые позволяют ключи, спускаясь по источникам,
// пока какой-нибудь не отдаст файл
func Fetch(ctx context.Context, dir string, keys Keys) (Set, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Set{}, err
	}
	var out Set
	var failed error

	for _, src := range citySources(keys) {
		path, err := src.fetch(ctx, dir)
		if err == nil {
			out.CityPath = path
			break
		}
		failed = err
	}
	for _, src := range asnSources(keys) {
		path, err := src.fetch(ctx, dir)
		if err == nil {
			out.ASNPath = path
			break
		}
		failed = err
	}
	if out.CityPath == "" {
		return out, fmt.Errorf("geo: no city database: %w", failed)
	}
	return out, nil
}

// source - один скачиваемый источник базы
type source struct {
	// name is the local file stem, so a database swapped for a better one
	// replaces the file rather than piling up beside it
	name string
	url  string
	// tarMember is set when the download is a tarball with the mmdb inside,
	// which is how MaxMind ships
	tarMember string
}

func citySources(keys Keys) []source {
	var out []source
	if keys.MaxMind != "" {
		// Paid first: GeoIP2-City is the same schema as GeoLite2-City with
		// materially better accuracy, and an account that has it should not be
		// served the free one
		out = append(out,
			maxmindSource("city", "GeoIP2-City", keys.MaxMind),
			maxmindSource("city", "GeoLite2-City", keys.MaxMind),
		)
	}
	if keys.DBIP != "" {
		out = append(out, source{
			name: "city",
			url:  fmt.Sprintf("https://db-ip.com/account/%s/db/ip-to-location/mmdb", keys.DBIP),
		})
	}
	stamp := time.Now().UTC().Format("2006-01")
	prev := time.Now().UTC().AddDate(0, -1, 0).Format("2006-01")
	// Free and keyless. Published monthly, and the current month is not there in
	// the first days of it, so the previous one is the fallback
	out = append(out,
		source{name: "city", url: "https://download.db-ip.com/free/dbip-city-lite-" + stamp + ".mmdb.gz"},
		source{name: "city", url: "https://download.db-ip.com/free/dbip-city-lite-" + prev + ".mmdb.gz"},
	)
	return out
}

func asnSources(keys Keys) []source {
	var out []source
	if keys.MaxMind != "" {
		// ISP carries the provider's own name and its organization, which is
		// what tells one regional arm of a carrier from another; ASN alone gives
		// only the number
		out = append(out,
			maxmindSource("asn", "GeoIP2-ISP", keys.MaxMind),
			maxmindSource("asn", "GeoLite2-ASN", keys.MaxMind),
		)
	}
	if keys.DBIP != "" {
		out = append(out, source{
			name: "asn",
			url:  fmt.Sprintf("https://db-ip.com/account/%s/db/ip-to-isp/mmdb", keys.DBIP),
		})
	}
	stamp := time.Now().UTC().Format("2006-01")
	prev := time.Now().UTC().AddDate(0, -1, 0).Format("2006-01")
	out = append(out,
		source{name: "asn", url: "https://download.db-ip.com/free/dbip-asn-lite-" + stamp + ".mmdb.gz"},
		source{name: "asn", url: "https://download.db-ip.com/free/dbip-asn-lite-" + prev + ".mmdb.gz"},
	)
	return out
}

func maxmindSource(name, edition, key string) source {
	return source{
		name: name,
		url: "https://download.maxmind.com/app/geoip_download?edition_id=" + edition +
			"&license_key=" + key + "&suffix=tar.gz",
		tarMember: edition + ".mmdb",
	}
}

// stale - срок доверия скачанной базе: месяц, с той же частотой их публикуют
const stale = 30 * 24 * time.Hour

func (s source) fetch(ctx context.Context, dir string) (string, error) {
	dest := filepath.Join(dir, s.name+".mmdb")
	if info, err := os.Stat(dest); err == nil && time.Since(info.ModTime()) < stale {
		return dest, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// The URL carries a license key, so the error must name the database and
		// not the request
		return "", fmt.Errorf("geo: %s: %s", s.name, resp.Status)
	}

	tmp := dest + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	err = s.extract(io.LimitReader(resp.Body, maxDownload), out)
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func (s source) extract(body io.Reader, out io.Writer) error {
	if !strings.HasSuffix(s.url, ".gz") && s.tarMember == "" {
		_, err := io.Copy(out, body)
		return err
	}
	gz, err := gzip.NewReader(body)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	if s.tarMember == "" {
		_, err := io.Copy(out, gz)
		return err
	}
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("geo: %s not found in archive", s.tarMember)
		}
		if err != nil {
			return err
		}
		if filepath.Base(header.Name) != s.tarMember {
			continue
		}
		_, err = io.Copy(out, reader)
		return err
	}
}
