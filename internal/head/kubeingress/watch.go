package kubeingress

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"
)

// NodeRoute is what the head knows about one node that serves behind the ingress
type NodeRoute struct {
	NodeID     string
	ServerName string
}

// Source is the head's own view of the fleet
type Source func() []NodeRoute

// Watcher keeps the route in step with the fleet. On a timer, not on every
// change: the set is small and one rewrite costs a single API call.
type Watcher struct {
	client  *Client
	source  Source
	name    string
	service string
	port    uint32
	every   time.Duration
	last    string
}

// Options configures a Watcher
type Options struct {
	Client *Client
	Source Source
	// Name of the IngressRouteTCP this owns
	Name string
	// Service and Port keep the connection on the host it arrived at
	Service string
	Port    uint32
	Every   time.Duration
}

// New builds a watcher
func NewWatcher(o Options) *Watcher {
	every := o.Every
	if every <= 0 {
		every = time.Minute
	}
	return &Watcher{
		client: o.Client, source: o.Source, name: o.Name,
		service: o.Service, port: o.Port, every: every,
	}
}

// Run reconciles until ctx is done
func (w *Watcher) Run(ctx context.Context) {
	w.reconcile(ctx)
	ticker := time.NewTicker(w.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.reconcile(ctx)
		}
	}
}

func (w *Watcher) reconcile(ctx context.Context) {
	nodes := w.source()
	names := make([]string, 0, len(nodes))
	seen := map[string]bool{}
	for _, n := range nodes {
		host := hostOnly(n.ServerName)
		// Один SNI дважды Traefik принимать не обязан
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		names = append(names, host)
	}
	sort.Strings(names)

	// Ничего не изменилось - незачем трогать kube-api каждую минуту
	fingerprint := strings.Join(names, ",")
	if fingerprint == w.last {
		return
	}

	routes := make([]Route, 0, len(names))
	for _, host := range names {
		routes = append(routes, Route{ServerName: host, Service: w.service, Port: w.port})
	}
	if err := w.client.Apply(ctx, w.name, routes); err != nil {
		log.Printf("kubeingress: could not update the route: %v", err)
		return
	}
	w.last = fingerprint
	log.Printf("kubeingress: route now covers %d server names", len(names))
}

// hostOnly strips the port: an SNI is a name, never an endpoint
func hostOnly(dest string) string {
	if i := strings.LastIndex(dest, ":"); i > 0 {
		return dest[:i]
	}
	return dest
}
