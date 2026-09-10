package subs

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWantsPage(t *testing.T) {
	cases := []struct {
		name   string
		accept string
		agent  string
		query  string
		want   bool
	}{
		{"браузер", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Mozilla/5.0", "", true},
		{"HttpURLConnection", "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2", "WINGS-V/1.0", "", false},
		{"голый клиент", "*/*", "v2rayNG/1.8.0", "", false},
		{"без заголовков", "", "", "", false},
		{"явный конфиг", "application/x-wingsv-config", "Mozilla/5.0", "", false},
		{"format=raw", "text/html,application/xhtml+xml", "Mozilla/5.0", "?format=raw", false},
		{"format=page", "*/*", "curl/8.0", "?format=page", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/sub/token"+c.query, nil)
			if c.accept != "" {
				r.Header.Set("Accept", c.accept)
			}
			if c.agent != "" {
				r.Header.Set("User-Agent", c.agent)
			}
			if got := wantsPage(r); got != c.want {
				t.Fatalf("wantsPage = %v, want %v", got, c.want)
			}
		})
	}
}
