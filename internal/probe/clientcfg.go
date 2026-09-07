// Package probe is the vantage-point role: a machine inside the censored network
// that measures donated nodes the way a real user reaches them.
//
// It measures by pulling bytes through the node, not by checking a handshake.
// Nodes are far more often shaped than blocked: the handshake completes, the
// ping looks excellent, and the user gets kilobytes a second. A reachability
// check that only asks "did it connect" reports that node as healthy
package probe

import (
	"encoding/json"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// clientConfig renders an Xray that dials one target and offers it locally as a
// SOCKS proxy, so the measurement runs over the same path a user would take
func clientConfig(target *fedpb.ProbeTarget, socksPort int) ([]byte, error) {
	stream := map[string]any{
		"network":  transportOf(target),
		"security": "reality",
		"realitySettings": map[string]any{
			"serverName":  target.GetServerName(),
			"publicKey":   target.GetRealityPublicKey(),
			"shortId":     target.GetShortId(),
			"fingerprint": "chrome",
			"spiderX":     "/",
		},
	}
	if verify := target.GetMldsa65Verify(); verify != "" {
		// A node configured with post-quantum verification refuses a client that
		// omits it, and that failure is the probe's fault rather than the node's
		stream["realitySettings"].(map[string]any)["mldsa65Verify"] = verify
	}
	if transportOf(target) == "xhttp" {
		stream["xhttpSettings"] = map[string]any{
			"path": pathOr(target.GetXhttpPath()),
			"mode": "auto",
		}
	}

	doc := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []map[string]any{{
			"tag":      "socks",
			"listen":   "127.0.0.1",
			"port":     socksPort,
			"protocol": "socks",
			"settings": map[string]any{"udp": false},
		}},
		"outbounds": []map[string]any{{
			"tag":      "measured",
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []map[string]any{{
					"address": target.GetHost(),
					"port":    target.GetPort(),
					"users": []map[string]any{{
						"id":         target.GetUuid(),
						"encryption": "none",
						"flow":       target.GetFlow(),
					}},
				}},
			},
			"streamSettings": stream,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func transportOf(target *fedpb.ProbeTarget) string {
	if t := target.GetTransport(); t != "" {
		return t
	}
	return "tcp"
}

func pathOr(path string) string {
	if path != "" {
		return path
	}
	return "/"
}
