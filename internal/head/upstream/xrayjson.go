package upstream

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Часть продавцов отдаёт подписку не ссылками, а готовыми конфигами ядра: массив
// объектов, у каждого свои outbounds. Ссылки там нет вообще, её надо собрать из
// полей самому.
//
// Разбираем мягко: чего не хватает - пропускаем, чужие поля не трогаем. Формат у
// всех немного свой, и требовать от продавца канонический вид бессмысленно

// xrayConfig - то немногое, что нам нужно от чужого конфига
type xrayConfig struct {
	// Remarks - как продавец назвал этот сервер. В имя не берём: у нас своё
	// название, от вендора
	Remarks   string          `json:"remarks"`
	Outbounds []xrayOutHolder `json:"outbounds"`
}

type xrayOutHolder struct {
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *streamSettings `json:"streamSettings"`
}

// vlessSettings покрывает оба вида: и плоский, где адрес лежит прямо в
// настройках, и классический с vnext
type vlessSettings struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ID         string `json:"id"`
	Flow       string `json:"flow"`
	Encryption string `json:"encryption"`
	Vnext      []struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Users   []struct {
			ID         string `json:"id"`
			Flow       string `json:"flow"`
			Encryption string `json:"encryption"`
		} `json:"users"`
	} `json:"vnext"`
}

type streamSettings struct {
	Network  string `json:"network"`
	Security string `json:"security"`
	Reality  *struct {
		PublicKey     string `json:"publicKey"`
		ShortID       string `json:"shortId"`
		ServerName    string `json:"serverName"`
		Fingerprint   string `json:"fingerprint"`
		SpiderX       string `json:"spiderX"`
		Mldsa65Verify string `json:"mldsa65Verify"`
	} `json:"realitySettings"`
	TLS *struct {
		ServerName  string   `json:"serverName"`
		Fingerprint string   `json:"fingerprint"`
		ALPN        []string `json:"alpn"`
	} `json:"tlsSettings"`
	WS *struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"wsSettings"`
	XHTTP *struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"xhttpSettings"`
	GRPC *struct {
		ServiceName string `json:"serviceName"`
	} `json:"grpcSettings"`
}

// linksFromConfigs собирает ссылки из массива чужих конфигов
func linksFromConfigs(body []byte) []string {
	var configs []xrayConfig
	if err := json.Unmarshal(body, &configs); err != nil {
		// Бывает и один конфиг без массива
		var single xrayConfig
		if json.Unmarshal(body, &single) != nil || len(single.Outbounds) == 0 {
			return nil
		}
		configs = []xrayConfig{single}
	}
	var out []string
	for _, cfg := range configs {
		for _, ob := range cfg.Outbounds {
			if !strings.EqualFold(ob.Protocol, "vless") {
				// Остальные протоколы пока мимо: собрать ссылку можно и для
				// них, но городить это до первого живого продавца незачем
				continue
			}
			if link := vlessLink(ob, cfg.Remarks); link != "" {
				out = append(out, link)
			}
		}
	}
	return out
}

// vlessLink собирает ссылку из исходящего
func vlessLink(ob xrayOutHolder, remarks string) string {
	var settings vlessSettings
	if len(ob.Settings) > 0 {
		_ = json.Unmarshal(ob.Settings, &settings)
	}
	address, port, id, flow, encryption := settings.Address, settings.Port, settings.ID, settings.Flow, settings.Encryption
	if len(settings.Vnext) > 0 {
		host := settings.Vnext[0]
		address, port = host.Address, host.Port
		if len(host.Users) > 0 {
			id, flow, encryption = host.Users[0].ID, host.Users[0].Flow, host.Users[0].Encryption
		}
	}
	if address == "" || port == 0 || id == "" {
		return ""
	}

	query := map[string]string{}
	if encryption != "" {
		query["encryption"] = encryption
	} else {
		query["encryption"] = "none"
	}
	if flow != "" {
		query["flow"] = flow
	}
	if stream := ob.StreamSettings; stream != nil {
		network := stream.Network
		if network == "" {
			network = "tcp"
		}
		query["type"] = network
		if stream.Security != "" {
			query["security"] = stream.Security
		}
		if r := stream.Reality; r != nil {
			putIf(query, "pbk", r.PublicKey)
			putIf(query, "sid", r.ShortID)
			putIf(query, "sni", r.ServerName)
			putIf(query, "fp", r.Fingerprint)
			putIf(query, "spx", r.SpiderX)
			// Постквантовая подпись едет своим параметром: без неё клиент не
			// сойдётся с сервером, который её требует
			putIf(query, "pqv", r.Mldsa65Verify)
		}
		if t := stream.TLS; t != nil {
			putIf(query, "sni", t.ServerName)
			putIf(query, "fp", t.Fingerprint)
			if len(t.ALPN) > 0 {
				query["alpn"] = strings.Join(t.ALPN, ",")
			}
		}
		if w := stream.WS; w != nil {
			putIf(query, "path", w.Path)
			putIf(query, "host", w.Host)
		}
		if x := stream.XHTTP; x != nil {
			putIf(query, "path", x.Path)
			putIf(query, "host", x.Host)
		}
		if g := stream.GRPC; g != nil {
			putIf(query, "serviceName", g.ServiceName)
		}
	}

	// Параметры в устойчивом порядке: иначе одна и та же подписка даёт разные
	// строки от чтения к чтению, и человеку кажется, что сервер сменился
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+url.QueryEscape(query[key]))
	}

	link := fmt.Sprintf("vless://%s@%s:%d?%s", id, address, port, strings.Join(parts, "&"))
	if remarks != "" {
		link += "#" + remarks
	}
	return link
}

func putIf(into map[string]string, key, value string) {
	if value != "" {
		into[key] = value
	}
}
