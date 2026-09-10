package binfetch

import (
	"archive/zip"
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func serve(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchVerifiesDigest(t *testing.T) {
	payload := []byte("#!/bin/sh\necho hi\n")
	sum := sha512.Sum512(payload)
	srv := serve(t, payload)
	c := New(t.TempDir())

	path, err := c.Fetch(srv.URL+"/bin", "xray", hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("installed file does not match what was served")
	}
}

// The file is about to run as root on somebody else's server, so a mismatch has
// to stop everything rather than be logged and ignored
func TestFetchRefusesWrongDigest(t *testing.T) {
	srv := serve(t, []byte("tampered"))
	c := New(t.TempDir())
	wrong := hex.EncodeToString(make([]byte, 64))
	if _, err := c.Fetch(srv.URL+"/bin", "xray", wrong); err != ErrDigestMismatch {
		t.Errorf("err = %v, want ErrDigestMismatch", err)
	}
	if _, ok := c.Installed("xray"); ok {
		t.Error("a binary with a bad digest was installed anyway")
	}
}

func TestFetchExtractsFromZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("xray")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("binary-body")); err != nil {
		t.Fatal(err)
	}
	// Release archives carry more than the binary; the rest must be ignored
	other, _ := zw.Create("geoip.dat")
	_, _ = other.Write([]byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	srv := serve(t, buf.Bytes())
	c := New(t.TempDir())
	path, err := c.Fetch(srv.URL+"/Xray-linux-64.zip", "xray", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary-body" {
		t.Errorf("extracted %q", got)
	}
}

// A crash mid-write must never leave a half-written executable the supervisor
// then runs
func TestInstallLeavesNoPartialFile(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)
	if _, err := c.install("xray", []byte("body")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
	info, err := os.Stat(filepath.Join(dir, "xray"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Error("installed binary is not executable")
	}
}

func TestFetchFailsOnHttpError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New(t.TempDir())
	if _, err := c.Fetch(srv.URL+"/missing", "xray", ""); err == nil {
		t.Error("a 404 was treated as success")
	}
}

func TestAssetNamesResolve(t *testing.T) {
	if _, err := XrayAsset(); err != nil {
		t.Errorf("no xray asset for this arch: %v", err)
	}
	if _, err := RelayAsset(); err != nil {
		t.Errorf("no relay asset for this arch: %v", err)
	}
}

// Xray разворачивает geoip:private через geoip.dat и без файла падает при
// загрузке конфига. Нода при этом рапортует "конфиг применён" и не слушает ни
// одного порта - отказ, который никак не видно снаружи.
func TestDataFilesComeOutOfTheArchive(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"xray":        "binary",
		"geoip.dat":   "ip-db",
		"geosite.dat": "site-db",
		"README.md":   "не наше дело",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := extractDataFiles(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got["geoip.dat"]) != "ip-db" || string(got["geosite.dat"]) != "site-db" {
		t.Errorf("данные маршрутизации не извлеклись: %v", got)
	}
	// Архив - чужое содержимое, и распаковывать его целиком значит дать релизу
	// возможность класть произвольные файлы на пожертвованную машину
	if _, ok := got["README.md"]; ok {
		t.Error("из архива вытащили лишний файл")
	}
	if _, ok := got["xray"]; ok {
		t.Error("бинарь попал в набор файлов данных")
	}
}
