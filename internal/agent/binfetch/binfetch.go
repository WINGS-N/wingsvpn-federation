// Package binfetch downloads and installs the binaries the agent supervises.
//
// The installer deliberately does not do this: keeping it out of the shell means
// the head can pin a version per node, and a donor who joined months ago gets the
// build we want rather than whatever was current when they ran curl
package binfetch

import (
	"archive/zip"
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// ErrDigestMismatch means the download did not match the digest the head named.
// Refusing here matters more than usual: the file is about to be executed as
// root on somebody else's server
var ErrDigestMismatch = errors.New("binfetch: digest mismatch")

// Client fetches release assets
type Client struct {
	HTTP    *http.Client
	BinDir  string
	Timeout time.Duration
}

// New builds a client writing into dir
func New(dir string) *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 10 * time.Minute},
		BinDir:  dir,
		Timeout: 10 * time.Minute,
	}
}

// XrayAsset is the release asset name for this machine. Xray publishes its linux
// builds as Xray-linux-64.zip rather than by GOARCH
func XrayAsset() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "Xray-linux-64.zip", nil
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	case "arm":
		return "Xray-linux-arm32-v7a.zip", nil
	default:
		return "", fmt.Errorf("binfetch: no xray build for %s", runtime.GOARCH)
	}
}

// RelayAsset is the vk-turn-server asset name for this machine
func RelayAsset() (string, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return "server-linux-" + runtime.GOARCH, nil
	default:
		return "", fmt.Errorf("binfetch: no relay build for %s", runtime.GOARCH)
	}
}

// Fetch downloads url, checks its SHA-512 when one was given, and installs it at
// name inside BinDir. An empty digest is allowed but logged by the caller: it
// means the head did not pin the build
func (c *Client) Fetch(url, name, sha512Hex string) (string, error) {
	body, err := c.get(url)
	if err != nil {
		return "", err
	}
	if sha512Hex != "" {
		sum := sha512.Sum512(body)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), sha512Hex) {
			return "", ErrDigestMismatch
		}
	}
	if strings.HasSuffix(url, ".zip") {
		// Данные маршрутизации лежат в том же архиве и нужны Xray на старте:
		// правило geoip:private он разворачивает через geoip.dat, и без файла
		// падает при загрузке конфига. Нода при этом рапортует "конфиг
		// применён" и не слушает ни одного порта - отказ, который видно только
		// если запустить xray -test руками.
		if extra, extraErr := extractDataFiles(body); extraErr == nil {
			for fileName, content := range extra {
				if _, writeErr := c.install(fileName, content); writeErr != nil {
					return "", writeErr
				}
			}
		}
		body, err = extractFromZip(body, name)
		if err != nil {
			return "", err
		}
	}
	return c.install(name, body)
}

func (c *Client) get(url string) ([]byte, error) {
	resp, err := c.HTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("binfetch: %s: http %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// extractFromZip pulls one member out of a release archive
func extractFromZip(data []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("binfetch: %s not found in archive", name)
}

// HasRoutingData reports whether the databases Xray needs at startup are next
// to the binary. Checked separately from the binary because an agent updated
// from an older version has one without the others.
func (c *Client) HasRoutingData() bool {
	for _, name := range dataFiles {
		if _, err := os.Stat(filepath.Join(c.BinDir, name)); err != nil {
			return false
		}
	}
	return true
}

// dataFiles are the routing databases Xray loads at startup. Named explicitly
// rather than "everything that is not the binary": an archive is somebody else's
// content, and unpacking it wholesale is how a release becomes a way to drop
// files onto a donated machine.
var dataFiles = []string{"geoip.dat", "geosite.dat"}

// extractDataFiles pulls the routing databases out of a release archive. A
// missing one is not an error: an archive without them is a build that does not
// need them.
func extractDataFiles(data []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if !slices.Contains(dataFiles, base) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		content, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		out[base] = content
	}
	return out, nil
}

// install writes the binary and swaps it into place atomically, so a crash
// mid-write cannot leave a half-written executable that the supervisor then runs
func (c *Client) install(name string, body []byte) (string, error) {
	if err := os.MkdirAll(c.BinDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(c.BinDir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

// Installed reports the path if the binary is already there
func (c *Client) Installed(name string) (string, bool) {
	path := filepath.Join(c.BinDir, name)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return "", false
	}
	return path, true
}
