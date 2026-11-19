package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"wingsnet.org/federation/internal/agent/binfetch"
)

const agentReleaseBase = "https://github.com/WINGS-N/wingsvpn-federation/releases/latest/download/"

func runUpdate(args []string) error {
	fs := newFlagSet("update")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: wingsv-fed update")
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("no standalone release for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	fetcher := binfetch.New(filepath.Dir(executable))
	asset := agentReleaseBase + "wingsv-fed-linux-" + runtime.GOARCH
	digest, err := updateDigest(fetcher.HTTP, asset+".sha512")
	if err != nil {
		return err
	}
	path, err := fetcher.Fetch(asset, filepath.Base(executable), digest)
	if err != nil {
		return err
	}
	fmt.Printf("Updated %s. Restart the service to run the new binary.\n", path)
	return nil
}

func updateDigest(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("release checksum: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}
	digest := strings.TrimSpace(string(body))
	sum, err := hex.DecodeString(digest)
	if err != nil || len(sum) != sha512.Size {
		return "", fmt.Errorf("invalid release SHA-512")
	}
	return digest, nil
}
