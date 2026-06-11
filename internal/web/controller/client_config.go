package controller

import (
	"encoding/json"
	"net"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

var serverInboundTags = map[string]bool{
	"api":          true,
	"metrics_out":  true,
	"metrics-in":   true,
	"panel-egress": true,
}

func resolveEndpoint(host string, inbound *model.Inbound) (address string, port int) {
	address = clientAddress(host, inbound)
	port = inbound.Port

	if inbound.NodeID != nil {
		var node model.Node
		if err := database.GetDB().First(&node, *inbound.NodeID).Error; err == nil && node.Address != "" {
			address = node.Address
		}
	}

	if listenIsInternalOnly(inbound.Listen) {
		var rule model.InboundFallback
		if err := database.GetDB().
			Where("child_id = ?", inbound.Id).
			Order("sort_order ASC, id ASC").
			First(&rule).Error; err == nil {
			var master model.Inbound
			if err := database.GetDB().First(&master, rule.MasterId).Error; err == nil {
				address, port = resolveEndpoint(host, &master)
			}
		}
	}
	return
}

func listenIsInternalOnly(listen string) bool {
	if listen == "" {
		return false
	}
	if listen[0] == '@' || listen[0] == '/' {
		return true
	}
	ip := net.ParseIP(listen)
	return ip != nil && ip.IsLoopback()
}

func buildClientConfig(address string, port int, inbound *model.Inbound, client *model.ClientRecord, templateJSON string, subOutbounds []any) map[string]any {
	var tmpl map[string]any
	json.Unmarshal([]byte(templateJSON), &tmpl)

	proxyTag := "proxy"
	inboundTag := inbound.Tag
	if inboundTag != "" {
		proxyTag = inboundTag
	}
	proxyOutbound := buildOutbound(address, port, proxyTag, inbound, client)

	cfg := make(map[string]any)

	if log, ok := tmpl["log"]; ok {
		cfg["log"] = log
	} else {
		cfg["log"] = map[string]any{"loglevel": "warning"}
	}

	cfg["inbounds"] = []any{
		map[string]any{
			"tag":      "socks-in",
			"port":     10808,
			"listen":   "127.0.0.1",
			"protocol": "socks",
			"settings": map[string]any{
				"auth": "noauth",
				"udp":  true,
			},
		},
	}

	var outbounds []any
	outbounds = append(outbounds, proxyOutbound)
	if tmplOutbounds, ok := tmpl["outbounds"].([]any); ok {
		for _, ob := range tmplOutbounds {
			obMap, _ := ob.(map[string]any)
			if obMap == nil {
				continue
			}
			tag, _ := obMap["tag"].(string)
			if tag == "" || serverInboundTags[tag] || tag == proxyTag || tag == "proxy" {
				continue
			}
			outbounds = append(outbounds, ob)
		}
	}
	for _, ob := range subOutbounds {
		obMap, _ := ob.(map[string]any)
		if obMap == nil {
			continue
		}
		tag, _ := obMap["tag"].(string)
		if tag == "" || tag == proxyTag || tag == "proxy" {
			continue
		}
		outbounds = append(outbounds, ob)
	}
	cfg["outbounds"] = outbounds

	var rules []any
	if tmplRouting, ok := tmpl["routing"].(map[string]any); ok {
		dmnStrategy, _ := tmplRouting["domainStrategy"].(string)
		if dmnStrategy == "" {
			dmnStrategy = "AsIs"
		}
		if tmplRules, ok := tmplRouting["rules"].([]any); ok {
			for _, r := range tmplRules {
				rMap, _ := r.(map[string]any)
				if rMap == nil {
					continue
				}
				inboundTags, _ := rMap["inboundTag"].([]any)
				skip := false
				for _, t := range inboundTags {
					if tagStr, ok := t.(string); ok && serverInboundTags[tagStr] {
						skip = true
						break
					}
				}
				if !skip {
					rules = append(rules, r)
				}
			}
		}
		cfg["routing"] = map[string]any{
			"domainStrategy": dmnStrategy,
			"rules":          rules,
		}
	} else {
		cfg["routing"] = map[string]any{
			"domainStrategy": "AsIs",
		}
	}

	for _, section := range []string{"dns", "policy", "fakedns", "transport", "observatory", "burstObservatory"} {
		if val, ok := tmpl[section]; ok {
			cfg[section] = val
		}
	}

	return cfg
}

func clientAddress(host string, inbound *model.Inbound) string {
	listen := inbound.Listen
	if listen == "" || listen == "0.0.0.0" || listen == "::" {
		return host
	}
	ip := net.ParseIP(listen)
	if ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return host
	}
	return listen
}

func buildOutbound(address string, port int, tag string, inbound *model.Inbound, client *model.ClientRecord) map[string]any {
	outbound := map[string]any{
		"tag":      tag,
		"protocol": string(inbound.Protocol),
		"settings": outboundSettings(address, port, inbound, client),
	}

	if inbound.StreamSettings != "" {
		var ss map[string]any
		if err := json.Unmarshal([]byte(inbound.StreamSettings), &ss); err == nil {
			cleanStreamSettings(ss)
			outbound["streamSettings"] = ss
		}
	}

	if inbound.Protocol == model.VLESS || inbound.Protocol == model.VMESS ||
		inbound.Protocol == model.Trojan || inbound.Protocol == model.Shadowsocks {
		outbound["mux"] = map[string]any{
			"enabled":     true,
			"concurrency": 8,
		}
	}

	return outbound
}

func outboundSettings(address string, port int, inbound *model.Inbound, client *model.ClientRecord) map[string]any {
	switch inbound.Protocol {
	case model.VLESS:
		user := map[string]any{
			"id":         client.UUID,
			"encryption": "none",
		}
		if client.Flow != "" {
			user["flow"] = client.Flow
		}
		return map[string]any{
			"vnext": []any{
				map[string]any{
					"address": address,
					"port":    port,
					"users":   []any{user},
				},
			},
		}

	case model.VMESS:
		return map[string]any{
			"vnext": []any{
				map[string]any{
					"address": address,
					"port":    port,
					"users": []any{
						map[string]any{
							"id":       client.UUID,
							"security": "auto",
							"alterId":  0,
						},
					},
				},
			},
		}

	case model.Trojan:
		srv := map[string]any{
			"address":  address,
			"port":     port,
			"password": client.Password,
		}
		if client.Flow != "" {
			srv["flow"] = client.Flow
		}
		return map[string]any{
			"servers": []any{srv},
		}

	case model.Shadowsocks:
		return map[string]any{
			"servers": []any{
				map[string]any{
					"address":  address,
					"port":     port,
					"method":   ssMethod(inbound.Settings),
					"password": client.Password,
				},
			},
		}

	case model.Hysteria:
		return hysteriaSettings(inbound, client, address, port)

	case model.Mixed, model.HTTP:
		return map[string]any{
			"servers": []any{
				map[string]any{
					"address": address,
					"port":    port,
				},
			},
		}

	case model.MTProto:
		secret := extractSecret(inbound.Settings)
		return map[string]any{
			"servers": []any{
				map[string]any{
					"address": address,
					"port":    port,
					"secret":  secret,
				},
			},
		}

	case model.WireGuard:
		return wireGuardSettings(inbound, client, address, port)

	case model.Tunnel:
		return map[string]any{
			"servers": []any{
				map[string]any{
					"address": address,
					"port":    port,
				},
			},
		}

	default:
		return map[string]any{}
	}
}

func ssMethod(settings string) string {
	if settings == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(settings), &m); err != nil {
		return ""
	}
	method, _ := m["method"].(string)
	return method
}

func extractSecret(settings string) string {
	if settings == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(settings), &m); err != nil {
		return ""
	}
	secret, _ := m["secret"].(string)
	return secret
}

func hysteriaSettings(inbound *model.Inbound, client *model.ClientRecord, address string, port int) map[string]any {
	ss := parseStreamSettings(inbound.StreamSettings)
	var version float64
	if v, ok := ss["version"].(float64); ok {
		version = v
	}
	if version >= 2 {
		return map[string]any{
			"server":   address,
			"port":     port,
			"password": client.Auth,
		}
	}
	return map[string]any{
		"servers": []any{
			map[string]any{
				"address":  address,
				"port":     port,
				"password": client.Auth,
			},
		},
	}
}

func parseStreamSettings(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}

func wireGuardSettings(inbound *model.Inbound, client *model.ClientRecord, address string, port int) map[string]any {
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return map[string]any{}
	}

	clients, _ := settings["clients"].([]any)
	privateKey := ""
	for _, c := range clients {
		cm, _ := c.(map[string]any)
		if cm == nil {
			continue
		}
		email, _ := cm["email"].(string)
		if email == client.Email {
			if pk, ok := cm["privateKey"].(string); ok {
				privateKey = pk
			}
			break
		}
	}

	serverInfo, _ := settings["server"].(map[string]any)
	serverPubKey, _ := serverInfo["publicKey"].(string)
	endpoint := serverInfo["endpoint"].(string)
	if endpoint == "" {
		endpoint = net.JoinHostPort(address, itoa(port))
	}

	addresses := computeWireGuardAddress(settings)
	if addresses == nil {
		addresses = []string{}
	}

	return map[string]any{
		"secretKey": privateKey,
		"address":   addresses,
		"peers": []any{
			map[string]any{
				"publicKey":  serverPubKey,
				"endpoint":   endpoint,
				"allowedIPs": []string{"0.0.0.0/0", "::/0"},
			},
		},
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func computeWireGuardAddress(settings map[string]any) []string {
	addrList, _ := settings["address"].([]any)
	if len(addrList) == 0 {
		return nil
	}
	firstAddr, _ := addrList[0].(string)
	if firstAddr == "" {
		return nil
	}
	ip, cidr, err := net.ParseCIDR(firstAddr)
	if err != nil {
		return nil
	}
	ones, _ := cidr.Mask.Size()
	next := make(net.IP, len(ip))
	copy(next, ip)
	ip4 := next.To4()
	if ip4 != nil {
		ip4[3]++
		if !cidr.Contains(ip4) {
			return nil
		}
		return []string{ip4.String() + "/" + itoa(ones)}
	}
	next[len(next)-1]++
	if !cidr.Contains(next) {
		return nil
	}
	return []string{next.String() + "/" + itoa(ones)}
}

func cleanStreamSettings(ss map[string]any) {
	if sockopt, ok := ss["sockopt"].(map[string]any); ok {
		delete(sockopt, "tproxy")
		delete(sockopt, "tcpFastOpen")
		if len(sockopt) == 0 {
			delete(ss, "sockopt")
		}
	}
	if settings, ok := ss["realitySettings"].(map[string]any); ok {
		if _, hasShortId := settings["shortId"]; !hasShortId {
			if _, hasServerName := settings["serverName"]; !hasServerName {
				delete(ss, "realitySettings")
			}
		}
	}
}
