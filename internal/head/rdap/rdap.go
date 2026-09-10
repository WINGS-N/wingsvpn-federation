// Package rdap узнаёт, когда домен зарегистрировали.
//
// Возраст - половина диагноза по фишингу и мошенническим лавкам: их домены
// живут неделю, а потом сгорают к хуям вместе с площадкой. Ни один фид за ними
// не поспевает, зато дата регистрации лежит в реестре и пиздеть не умеет.
//
// Спрашиваем с башки, а НЕ с ноды: нода про домены и так знает только то, что
// сама увидела, и слать её в реестр значит светить чужой хостинг ради чужого же
// запроса
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// bootstrapURL - откуда IANA раздаёт список RDAP-серверов по зонам. Один файл
// на весь интернет, обновляется редко
const bootstrapURL = "https://data.iana.org/rdap/dns.json"

// bootstrapTTL - как часто перечитываем список серверов. Зоны переезжают раз в
// сто лет, чаще туда ходить только зря дёргать IANA
const bootstrapTTL = 24 * time.Hour

// requestTimeout - реестры отвечают быстро, а висеть на молчащем незачем
const requestTimeout = 10 * time.Second

// ErrNoServer - у зоны нет RDAP-сервера. Так живёт куча национальных зон, и это
// не поломка, а просто хуй вам, а не ответ
var ErrNoServer = errors.New("rdap: the zone has no rdap server")

// ErrNotFound - реестр домена не знает
var ErrNotFound = errors.New("rdap: domain not found in the registry")

// Client спрашивает реестры о возрасте домена
type Client struct {
	http *http.Client
	mu   sync.Mutex
	// services - зона в адрес её RDAP-сервера
	services  map[string]string
	fetchedAt time.Time
	now       func() time.Time
}

func New() *Client {
	return &Client{
		http: &http.Client{Timeout: requestTimeout},
		now:  time.Now,
	}
}

// SetHTTP подменяет клиента. Нужно тестам, чтобы не ходить в живой реестр
func (c *Client) SetHTTP(client *http.Client) { c.http = client }

// Registered отдаёт дату регистрации домена
func (c *Client) Registered(ctx context.Context, domain string) (time.Time, error) {
	name := normalize(domain)
	if name == "" {
		return time.Time{}, ErrNotFound
	}
	base, err := c.serverFor(ctx, name)
	if err != nil {
		return time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"domain/"+name, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return time.Time{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("rdap: the registry answered %d", resp.StatusCode)
	}
	var body struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	// Потолок на тело: реестр может насыпать сколько угодно контактов и прочей
	// требухи, а нам нужна одна ебаная дата
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return time.Time{}, err
	}
	for _, event := range body.Events {
		if !strings.EqualFold(event.Action, "registration") {
			continue
		}
		at, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			return time.Time{}, err
		}
		return at.UTC(), nil
	}
	return time.Time{}, ErrNotFound
}

// serverFor ищет RDAP-сервер по зоне домена
func (c *Client) serverFor(ctx context.Context, domain string) (string, error) {
	if err := c.ensureBootstrap(ctx); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Идём справа налево: у некоторых зон свой сервер на второй уровень
	labels := strings.Split(domain, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		zone := strings.Join(labels[i:], ".")
		if base, ok := c.services[zone]; ok {
			return base, nil
		}
	}
	return "", ErrNoServer
}

// ensureBootstrap подтягивает список серверов, если он протух
func (c *Client) ensureBootstrap(ctx context.Context) error {
	c.mu.Lock()
	fresh := c.services != nil && c.now().Sub(c.fetchedAt) < bootstrapTTL
	c.mu.Unlock()
	if fresh {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bootstrapURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rdap: the server list answered %d", resp.StatusCode)
	}
	var body struct {
		// Каждая запись: [список зон, список адресов]
		Services [][2][]string `json:"services"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return err
	}
	services := make(map[string]string, 1024)
	for _, entry := range body.Services {
		zones, urls := entry[0], entry[1]
		if len(urls) == 0 {
			continue
		}
		base := urls[0]
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		for _, zone := range zones {
			services[strings.ToLower(strings.TrimSpace(zone))] = base
		}
	}
	if len(services) == 0 {
		return errors.New("rdap: the server list is empty")
	}
	c.mu.Lock()
	c.services, c.fetchedAt = services, c.now()
	c.mu.Unlock()
	return nil
}

func normalize(domain string) string {
	name := strings.ToLower(strings.TrimSpace(domain))
	name = strings.TrimSuffix(name, ".")
	if name == "" || !strings.Contains(name, ".") {
		return ""
	}
	// Спрашивать надо про сам домен, а не про хост: у www.example.com в реестре
	// записи нет, а у example.com есть. Резать по двум последним меткам нельзя
	// нахуй - у example.co.uk так получится co.uk, то есть сама зона
	registrable, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return registrable
}
