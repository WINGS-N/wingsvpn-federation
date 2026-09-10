// Package kubeingress keeps the Traefik route in step with the fleet.
//
// The route matches on SNI, and a node's dest changes when the head re-picks it.
// Written by hand the route goes stale, and the node then answers with Traefik's
// own certificate instead of the borrowed one.
package kubeingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	saDir     = "/var/run/secrets/kubernetes.io/serviceaccount"
	tokenFile = saDir + "/token"
	caFile    = saDir + "/ca.crt"
	nsFile    = saDir + "/namespace"

	// ownerLabel marks what this process may overwrite; anything without it was
	// made by hand
	ownerLabel = "app.kubernetes.io/managed-by"
	ownerValue = "wingsv-fed-head"
)

// Client talks to kube-api from inside the pod.
type Client struct {
	http      *http.Client
	host      string
	token     string
	namespace string
}

// Available reports whether we run inside a cluster. Outside one there is
// nothing to manage and no error to report.
func Available() bool {
	if _, err := os.Stat(tokenFile); err != nil {
		return false
	}
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// New builds a client from the pod's own credentials
func New() (*Client, error) {
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("kubeingress: cluster CA is not usable")
	}
	ns, err := os.ReadFile(nsFile)
	if err != nil {
		return nil, err
	}
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	return &Client{
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig(pool)},
		},
		host:      "https://" + host + ":" + port,
		token:     strings.TrimSpace(string(token)),
		namespace: strings.TrimSpace(string(ns)),
	}, nil
}

func tlsConfig(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// Route is which SNI reaches a node and where it listens
type Route struct {
	ServerName string
	Service    string
	Port       uint32
}

// Apply writes the IngressRouteTCP. One object for the whole fleet: a node that
// disappeared stops being routed without a separate delete.
func (c *Client) Apply(ctx context.Context, name string, routes []Route) error {
	if len(routes) == 0 {
		return nil
	}
	rules := make([]map[string]any, 0, len(routes))
	for _, r := range routes {
		rules = append(rules, map[string]any{
			"match": fmt.Sprintf("HostSNI(`%s`)", r.ServerName),
			"services": []map[string]any{{
				"name": r.Service,
				"port": r.Port,
				// v2: текстовый v1 не несёт TLV, а Xray принимает оба
				"proxyProtocol": map[string]any{"version": 2},
				// Без этого прокси срёт мимо ClusterIP прямо по эндпоинтам подов
				// и раскидывает клиента по всему флоту, а dest у каждой ноды
				// свой, и два раза из трёх человек прилетает к Xray, который
				// изображает совсем другой сайт, и хендшейк разъёбывается нахуй.
				// Внешне при этом всё зелёное, и хуй поймёшь, что оно сдохло.
				// Через ClusterIP работает internalTrafficPolicy, и соединение
				// никуда со своего узла не уёбывает
				"nativeLB": true,
			}},
		})
	}
	manifest := map[string]any{
		"apiVersion": "traefik.io/v1alpha1",
		"kind":       "IngressRouteTCP",
		"metadata": map[string]any{
			"name":      name,
			"namespace": c.namespace,
			"labels":    map[string]string{ownerLabel: ownerValue},
		},
		"spec": map[string]any{
			"entryPoints": []string{"websecure"},
			"routes":      rules,
			// Не расшифровываем: сертификат заимствован, и распаковка хендшейка
			// сломала бы саму идею REALITY
			"tls": map[string]any{"passthrough": true},
		},
	}
	return c.put(ctx, name, manifest)
}

func (c *Client) put(ctx context.Context, name string, manifest map[string]any) error {
	body, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/apis/traefik.io/v1alpha1/namespaces/%s/ingressroutetcps/%s",
		c.host, c.namespace, name)

	// Server-side apply: создаёт или обновляет, не трогая чужие поля
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		path+"?fieldManager="+ownerValue+"&force=true", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/apply-patch+yaml")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("kubeingress: %s: %s", path, resp.Status)
	}
	return nil
}

// Namespace is the pod's own namespace
func (c *Client) Namespace() string { return c.namespace }

// Apply writes any object with server-side apply. Path is everything after the
// api host, so a caller names the resource it owns
func (c *Client) ApplyRaw(ctx context.Context, path string, manifest map[string]any) ([]byte, error) {
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		c.host+path+"?fieldManager="+ownerValue+"&force=true", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/apply-patch+yaml")
	return c.do(req)
}

// GetRaw reads one object. A missing object comes back as nil without an error:
// the first holder of a lease creates it
func (c *Client) GetRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kubeingress: %s: %s", path, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// PutRaw replaces an object. Used where server-side apply cannot express the
// condition: a lease is only taken when the version it was read at still stands
func (c *Client) PutRaw(ctx context.Context, path string, manifest map[string]any) ([]byte, error) {
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.host+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

// PostRaw creates an object
func (c *Client) PostRaw(ctx context.Context, path string, manifest map[string]any) ([]byte, error) {
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kubeingress: %s: %s: %s", req.URL.Path, resp.Status, bytes.TrimSpace(raw))
	}
	return raw, nil
}

// PatchRaw applies a merge patch. Мелкие правки чужого объекта, где
// server-side apply отобрал бы у контроллера владение остальными полями
func (c *Client) PatchRaw(ctx context.Context, path string, patch map[string]any) error {
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.host+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/merge-patch+json")
	_, err = c.do(req)
	return err
}
