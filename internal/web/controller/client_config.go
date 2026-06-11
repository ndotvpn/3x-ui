package controller

import (
	"encoding/json"
	"net"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func buildClientConfig(host string, inbound *model.Inbound, client *model.ClientRecord) map[string]any {
	address := clientAddress(host, inbound)
	port := inbound.Port

	cfg := map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
		},
		"inbounds": []any{
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
		},
		"outbounds": []any{
			buildOutbound(address, port, inbound, client),
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{
					"type":        "field",
					"inboundTag":  []string{"socks-in"},
					"outboundTag": "proxy",
				},
			},
		},
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

func buildOutbound(address string, port int, inbound *model.Inbound, client *model.ClientRecord) map[string]any {
	outbound := map[string]any{
		"tag":      "proxy",
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
		return wireGuardSettings(inbound, client)

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

func wireGuardSettings(inbound *model.Inbound, client *model.ClientRecord) map[string]any {
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return map[string]any{}
	}

	serverInfo, _ := settings["server"].(map[string]any)
	serverPubKey, _ := serverInfo["publicKey"].(string)
	serverEndpoint, _ := serverInfo["endpoint"].(string)

	secretKey := client.UUID

	return map[string]any{
		"secretKey": secretKey,
		"address":   []string{},
		"peers": []any{
			map[string]any{
				"publicKey":  serverPubKey,
				"endpoint":   serverEndpoint,
				"allowedIPs": []string{"0.0.0.0/0", "::/0"},
			},
		},
	}
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


