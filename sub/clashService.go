package sub

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/HeadStone1/s-ui/database/model"
	"github.com/HeadStone1/s-ui/service"
	"github.com/HeadStone1/s-ui/util"

	"gopkg.in/yaml.v3"
)

type ClashService struct {
	service.SettingService
	JsonService
	LinkService
}

func stringSliceFromInterfaces(values []interface{}) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if item, ok := value.(string); ok {
			result = append(result, item)
		}
	}
	return result
}

const basicClashConfig = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
profile:
  store-selected: true
  store-fake-ip: true
tun:
  enable: false
  stack: system
  auto-route: true
  auto-detect-interface: true
  strict-route: true
  auto-redirect: true
  dns-hijack:
    - any:53
dns:
  enable: true
  ipv6: true
  prefer-h3: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
  nameserver:
    - https://doh.pub/dns-query
    - https://1.0.0.1/dns-query
  fallback:
    - tcp://9.9.9.9:53
  fake-ip-filter:
    - "*.lan"
    - localhost
    - "*.local"
rules:
  - GEOIP,Private,DIRECT
  - MATCH,Proxy
`

const ProxyGroups = `- name: Proxy
  type: select
  proxies: []
- name: Auto
  type: url-test
  proxies: []
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
`

func (s *ClashService) GetClash(subId string) (*string, []string, error) {
	subService := SubService{}
	client, err := subService.getClientBySubId(subId)
	if err != nil {
		return nil, nil, err
	}
	return s.GetClashForClient(client)
}

func (s *ClashService) GetClashForClient(client *model.Client) (*string, []string, error) {
	inDatas, err := s.getData(client)
	if err != nil {
		return nil, nil, err
	}

	outbounds, outTags, err := s.getOutbounds(client.Config, inDatas)
	if err != nil {
		return nil, nil, err
	}

	links := s.LinkService.GetLinks(&client.Links, "external", "")
	tagNumEnable := 0
	if len(links) > 1 {
		tagNumEnable = 1
	}
	for index, link := range links {
		json, tag, err := util.GetOutbound(link, (index+1)*tagNumEnable)
		if err == nil && len(tag) > 0 {
			*outbounds = append(*outbounds, *json)
			*outTags = append(*outTags, tag)
		}
	}

	basicConfig, err := s.getClashConfig()
	if err != nil || len(basicConfig) == 0 {
		basicConfig = basicClashConfig
	}
	basicConfig = s.ensureClashControllerSecret(basicConfig, client)

	resultStr, err := s.ConvertToClashMeta(outbounds, basicConfig)
	if err != nil {
		return nil, nil, err
	}

	updateInterval, _ := s.SettingService.GetSubUpdates()
	headers := util.GetHeaders(client, updateInterval)

	return &resultStr, headers, nil
}

func (s *ClashService) ensureClashControllerSecret(config string, client *model.Client) string {
	var output map[string]interface{}
	if err := yaml.Unmarshal([]byte(config), &output); err != nil {
		return config
	}
	controller, _ := output["external-controller"].(string)
	if controller == "" {
		return config
	}
	secret, _ := output["secret"].(string)
	if secret == "" && client != nil && client.SubSecret != "" {
		// Derive a separate controller password. Do not copy either the
		// subscription credential or the panel's session-signing secret into a
		// downloadable Clash profile.
		digest := sha256.Sum256([]byte(client.SubSecret))
		output["secret"] = hex.EncodeToString(digest[:])
	}
	result, err := yaml.Marshal(output)
	if err != nil {
		return config
	}
	return string(result)
}

func (s *ClashService) getClashConfig() (string, error) {
	subClashExt, err := s.SettingService.GetSubClashExt()
	if err != nil {
		return "", err
	}

	return subClashExt, nil
}

func (s *ClashService) ConvertToClashMeta(outbounds *[]map[string]interface{}, basicConfig string) (string, error) {
	var proxies []interface{}
	proxyTags := make([]string, 0)
	for _, obMap := range *outbounds {

		t, _ := obMap["type"].(string)
		if t == "selector" || t == "urltest" || t == "direct" {
			continue
		}

		tag, _ := obMap["tag"].(string)
		if tag == "" {
			continue
		}

		proxy := make(map[string]interface{})
		proxy["name"] = tag
		proxy["type"] = t

		server, _ := obMap["server"].(string)
		server = strings.TrimPrefix(strings.TrimSuffix(server, "]"), "[")
		proxy["server"] = server

		if port, ok := integerValue(obMap["server_port"]); ok && port > 0 && port <= 65535 {
			proxy["port"] = port
		} else {
			continue
		}

		switch t {
		case "vmess", "vless", "tuic":
			proxy["uuid"] = obMap["uuid"]
			proxy["udp"] = true
			if t == "vmess" {
				if alterID, ok := integerValue(obMap["alter_id"]); ok {
					proxy["alterId"] = alterID
				} else {
					proxy["alterId"] = 0
				}
				proxy["cipher"] = "auto"
				copyOutboundOption(obMap, proxy, "packet_encoding", "packet-encoding")
				copyOutboundOption(obMap, proxy, "global_padding", "global-padding")
				copyOutboundOption(obMap, proxy, "authenticated_length", "authenticated-length")
			}
			if t == "vless" {
				copyOutboundOption(obMap, proxy, "packet_encoding", "packet-encoding")
				copyOutboundOption(obMap, proxy, "encryption", "encryption")
				if flow, ok := obMap["flow"].(string); ok {
					proxy["flow"] = flow
				}
			}
			if t == "tuic" {
				proxy["password"] = obMap["password"]
				if congestion_control, ok := obMap["congestion_control"].(string); ok {
					proxy["congestion-controller"] = congestion_control
				}
			}
		case "trojan":
			proxy["password"] = obMap["password"]
			proxy["udp"] = true
		case "socks", "http":
			if t == "socks" {
				proxy["type"] = "socks5"
			}
			proxy["username"] = obMap["username"]
			proxy["password"] = obMap["password"]
		case "hysteria", "hysteria2":
			proxy["udp"] = true
			copyNumberOption(obMap, proxy, "up_mbps", "up")
			copyNumberOption(obMap, proxy, "down_mbps", "down")
			if t == "hysteria" {
				proxy["auth-str"] = obMap["auth_str"]
				if obfs, ok := obMap["obfs"].(string); ok {
					proxy["obfs"] = obfs
				}
			} else {
				proxy["password"] = obMap["password"]
				if obfs, ok := obMap["obfs"].(map[string]interface{}); ok {
					proxy["obfs"] = obfs["type"]
					proxy["obfs-password"] = obfs["password"]
				}
			}

			if portLists := interfaceStringSlice(obMap["server_ports"]); len(portLists) > 0 {
				ports := make([]string, 0, len(portLists))
				for _, portRange := range portLists {
					ports = append(ports, strings.ReplaceAll(portRange, ":", "-"))
				}
				proxy["ports"] = strings.Join(ports, ",")
			}
		case "anytls":
			proxy["udp"] = true
			proxy["password"] = obMap["password"]
		case "shadowsocks":
			proxy["type"] = "ss"
			proxy["cipher"] = obMap["method"]
			proxy["password"] = obMap["password"]
			if network, ok := obMap["network"].(string); !ok || network != "tcp" {
				proxy["udp"] = true
			}
			if uot, ok := obMap["udp_over_tcp"].(bool); ok && uot {
				proxy["udp-over-tcp"] = true
			}
		default:
			continue
		}

		if ipVersion, ok := obMap["ip_version"].(string); ok && ipVersion != "" {
			proxy["ip-version"] = ipVersion
		}
		if tfo, ok := obMap["tcp_fast_open"].(bool); ok {
			proxy["tfo"] = tfo
		}
		if mptcp, ok := obMap["multipath_tcp"].(bool); ok {
			proxy["mptcp"] = mptcp
		}

		// TLS params
		tls, isTls := obMap["tls"].(map[string]interface{})
		if isTls {
			isTls, _ = tls["enabled"].(bool)
		}
		if isTls {
			proxy["tls"] = true

			// ALPN if exists
			if alpn := interfaceStringSlice(tls["alpn"]); len(alpn) > 0 {
				proxy["alpn"] = alpn
			}

			// Add reality if exists
			if reality, ok := tls["reality"].(map[string]interface{}); ok {
				realityEnabled, _ := reality["enabled"].(bool)
				if realityEnabled {
					realityOpts := make(map[string]interface{})
					if pbk, ok := reality["public_key"].(string); ok {
						realityOpts["public-key"] = pbk
					}
					if sid, ok := reality["short_id"].(string); ok {
						realityOpts["short-id"] = sid
					}
					proxy["reality-opts"] = realityOpts
				}
			}
			if utls, ok := tls["utls"].(map[string]interface{}); ok {
				if enabled, ok := utls["enabled"].(bool); ok && enabled {
					if fp, ok := utls["fingerprint"].(string); ok {
						proxy["client-fingerprint"] = fp
					}
				}
			}
			if sni, ok := tls["server_name"].(string); ok {
				if t == "vless" || t == "vmess" {
					proxy["servername"] = sni
				} else {
					proxy["sni"] = sni
				}
			}
			fingerprint := firstCSVValue(firstTLSString(tls, "xray_pinned_peer_cert_sha256", "certificate_sha256"))
			if fingerprint != "" {
				proxy["fingerprint"] = fingerprint
			} else if insecure, ok := tls["insecure"].(bool); ok && insecure {
				proxy["skip-cert-verify"] = true
			}
			if names := tlsStringList(tls, "xray_verify_peer_cert_by_name", "certificate_names"); len(names) > 0 {
				proxy["name-cert-verify"] = strings.TrimSpace(names[0])
			}
			// ech outbounds
			if ech, ok := tls["ech"].(map[string]interface{}); ok {
				echEnabled, _ := ech["enabled"].(bool)
				if echEnabled {
					echParts := interfaceStringSlice(ech["config"])
					echOpts := map[string]interface{}{
						"enable": true,
						"config": strings.Join(echParts, ""),
					}
					if queryServerName, ok := ech["query_server_name"].(string); ok && queryServerName != "" {
						echOpts["query-server-name"] = queryServerName
					}
					proxy["ech-opts"] = echOpts
				}
			}
		}

		// Transport if exist
		if transport, ok := obMap["transport"].(map[string]interface{}); ok {
			tt, _ := transport["type"].(string)
			switch tt {
			case "http":
				httpOpts := make(map[string]interface{})
				if path, ok := transport["path"].([]interface{}); ok {
					if len(path) > 0 {
						httpOpts["path"] = path[0]
					}
				} else if path, ok := transport["path"].(string); ok {
					httpOpts["path"] = path
				}
				if host, ok := transport["host"].([]interface{}); ok {
					httpOpts["host"] = stringSliceFromInterfaces(host)
				} else if host, ok := transport["host"].(string); ok && host != "" {
					httpOpts["host"] = []string{host}
				}
				if method, ok := transport["method"].(string); ok && method != "" {
					httpOpts["method"] = method
				}
				if headers, ok := transport["headers"].(map[string]interface{}); ok {
					httpOpts["headers"] = headers
				}
				if isTls {
					proxy["network"] = "h2"
					proxy["h2-opts"] = httpOpts
				} else {
					proxy["network"] = "http"
					proxy["http-opts"] = httpOpts
				}
			case "ws", "httpupgrade":
				proxy["network"] = "ws"
				wsOpts := make(map[string]interface{})
				if path, ok := transport["path"].(string); ok {
					wsOpts["path"] = path
				}
				if headers, ok := transport["headers"].([]interface{}); ok {
					wsOpts["headers"] = headers
				}
				if headers, ok := transport["headers"].(map[string]interface{}); ok {
					wsOpts["headers"] = headers
				}
				if maxEarlyData, ok := integerValue(transport["max_early_data"]); ok {
					wsOpts["max-early-data"] = maxEarlyData
				}
				if ed, ok := transport["early_data_header_name"].(string); ok {
					wsOpts["early-data-header-name"] = ed
				}
				if tt == "httpupgrade" {
					wsOpts["v2ray-http-upgrade"] = true
				}
				proxy["ws-opts"] = wsOpts
			case "grpc":
				proxy["network"] = "grpc"
				grpcOpts := make(map[string]interface{})
				if service_name, ok := transport["service_name"].(string); ok {
					grpcOpts["grpc-service-name"] = service_name
				}
				proxy["grpc-opts"] = grpcOpts
			case "xhttp":
				if t != "vless" {
					continue
				}
				proxy["network"] = "xhttp"
				proxy["xhttp-opts"] = buildMihomoXHTTPOptions(transport)
			}
		}

		// Multiplex
		if mux, ok := obMap["multiplex"].(map[string]interface{}); ok {
			if enabled, ok := mux["enabled"].(bool); ok && enabled {
				smux := make(map[string]interface{})
				smux["enabled"] = true
				if protocol, ok := mux["protocol"].(string); ok {
					smux["protocol"] = protocol
				}
				if _, ok := mux["max_connections"].(float64); ok {
					smux["max-connections"] = mux["max_connections"]
				}
				if _, ok := mux["min_streams"].(float64); ok {
					smux["min-streams"] = mux["min_streams"]
				}
				if _, ok := mux["max_streams"].(float64); ok {
					smux["max-streams"] = mux["max_streams"]
				}
				if _, ok := mux["padding"].(bool); ok {
					smux["padding"] = mux["padding"]
				}
				if brutal, ok := mux["brutal"].(map[string]interface{}); ok {
					if enabled, ok := brutal["enabled"].(bool); ok && enabled {
						brutalOpts := make(map[string]interface{})
						brutalOpts["enabled"] = true
						if _, ok := brutal["up_mbps"].(float64); ok {
							brutalOpts["up"] = brutal["up_mbps"]
						}
						if _, ok := brutal["down_mbps"].(float64); ok {
							brutalOpts["down"] = brutal["down_mbps"]
						}
						smux["brutal-opts"] = brutalOpts
					}
				}
				proxy["smux"] = smux
			}
		}

		proxies = append(proxies, proxy)
		proxyTags = append(proxyTags, tag)
	}

	var proxyGroups []map[string]interface{}
	err := yaml.Unmarshal([]byte(ProxyGroups), &proxyGroups)
	if err != nil {
		return "", err
	}

	proxyGroups[1]["proxies"] = proxyTags
	proxyGroups[0]["proxies"] = append([]string{proxyGroups[1]["name"].(string)}, proxyTags...)

	// Merge proxies and proxy groups if exist
	var output map[string]interface{}
	err = yaml.Unmarshal([]byte(basicConfig), &output)
	if err != nil {
		return "", err
	}
	if output == nil {
		output = make(map[string]interface{})
	}

	if p, ok := output["proxies"].([]interface{}); ok {
		output["proxies"] = append(p, proxies...)
	} else {
		output["proxies"] = proxies
	}

	if pg, ok := output["proxy-groups"].([]interface{}); ok {
		output["proxy-groups"] = append(pg, proxyGroups[0], proxyGroups[1])
	} else {
		output["proxy-groups"] = proxyGroups
	}

	result, err := yaml.Marshal(output)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func copyOutboundOption(source, target map[string]interface{}, sourceKey, targetKey string) {
	if value, ok := source[sourceKey]; ok && value != nil {
		target[targetKey] = value
	}
}

func firstTLSString(tls map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := tls[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
		if values, ok := tls[key].([]interface{}); ok && len(values) > 0 {
			if value, ok := values[0].(string); ok && strings.TrimSpace(value) != "" {
				return value
			}
		}
		if values, ok := tls[key].([]string); ok && len(values) > 0 && strings.TrimSpace(values[0]) != "" {
			return values[0]
		}
	}
	return ""
}

func tlsStringList(tls map[string]interface{}, keys ...string) []string {
	for _, key := range keys {
		switch value := tls[key].(type) {
		case string:
			if value != "" {
				return strings.Split(value, ",")
			}
		case []string:
			return value
		case []interface{}:
			return stringSliceFromInterfaces(value)
		}
	}
	return nil
}

func interfaceStringSlice(value interface{}) []string {
	switch values := value.(type) {
	case string:
		if values == "" {
			return nil
		}
		return []string{values}
	case []string:
		return values
	case []interface{}:
		return stringSliceFromInterfaces(values)
	default:
		return nil
	}
}

func integerValue(value interface{}) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, true
	case int32:
		return int(number), true
	case int64:
		return int(number), true
	case uint:
		return int(number), true
	case uint32:
		return int(number), true
	case uint64:
		return int(number), true
	case float64:
		return int(number), true
	case string:
		parsed, err := strconv.Atoi(number)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func copyNumberOption(source, target map[string]interface{}, sourceKey, targetKey string) {
	if value, ok := integerValue(source[sourceKey]); ok {
		target[targetKey] = value
	}
}

func firstCSVValue(value string) string {
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			return part
		}
	}
	return ""
}

var xhttpOptionAliases = map[string]string{
	"path":                     "path",
	"host":                     "host",
	"mode":                     "mode",
	"headers":                  "headers",
	"no_grpc_header":           "no-grpc-header",
	"noGRPCHeader":             "no-grpc-header",
	"x_padding_bytes":          "x-padding-bytes",
	"xPaddingBytes":            "x-padding-bytes",
	"x_padding_obfs_mode":      "x-padding-obfs-mode",
	"xPaddingObfsMode":         "x-padding-obfs-mode",
	"x_padding_key":            "x-padding-key",
	"xPaddingKey":              "x-padding-key",
	"x_padding_header":         "x-padding-header",
	"xPaddingHeader":           "x-padding-header",
	"x_padding_placement":      "x-padding-placement",
	"xPaddingPlacement":        "x-padding-placement",
	"x_padding_method":         "x-padding-method",
	"xPaddingMethod":           "x-padding-method",
	"uplink_http_method":       "uplink-http-method",
	"uplinkHTTPMethod":         "uplink-http-method",
	"session_placement":        "session-placement",
	"sessionPlacement":         "session-placement",
	"sessionIDPlacement":       "session-placement",
	"session_key":              "session-key",
	"sessionKey":               "session-key",
	"sessionIDKey":             "session-key",
	"session_table":            "session-table",
	"sessionTable":             "session-table",
	"sessionIDTable":           "session-table",
	"session_length":           "session-length",
	"sessionLength":            "session-length",
	"sessionIDLength":          "session-length",
	"seq_placement":            "seq-placement",
	"seqPlacement":             "seq-placement",
	"seq_key":                  "seq-key",
	"seqKey":                   "seq-key",
	"uplink_data_placement":    "uplink-data-placement",
	"uplinkDataPlacement":      "uplink-data-placement",
	"uplink_data_key":          "uplink-data-key",
	"uplinkDataKey":            "uplink-data-key",
	"uplink_chunk_size":        "uplink-chunk-size",
	"uplinkChunkSize":          "uplink-chunk-size",
	"sc_max_each_post_bytes":   "sc-max-each-post-bytes",
	"scMaxEachPostBytes":       "sc-max-each-post-bytes",
	"sc_min_posts_interval_ms": "sc-min-posts-interval-ms",
	"scMinPostsIntervalMs":     "sc-min-posts-interval-ms",
}

var xhttpReuseAliases = map[string]string{
	"maxConcurrency":      "max-concurrency",
	"maxConnections":      "max-connections",
	"cMaxReuseTimes":      "c-max-reuse-times",
	"hMaxRequestTimes":    "h-max-request-times",
	"hMaxReusableSecs":    "h-max-reusable-secs",
	"hKeepAlivePeriod":    "h-keep-alive-period",
	"max_concurrency":     "max-concurrency",
	"max_connections":     "max-connections",
	"c_max_reuse_times":   "c-max-reuse-times",
	"h_max_request_times": "h-max-request-times",
	"h_max_reusable_secs": "h-max-reusable-secs",
	"h_keep_alive_period": "h-keep-alive-period",
}

func buildMihomoXHTTPOptions(transport map[string]interface{}) map[string]interface{} {
	options := make(map[string]interface{})
	apply := func(source map[string]interface{}) {
		for key, value := range source {
			if target, ok := xhttpOptionAliases[key]; ok {
				options[target] = value
			}
		}
		if reuse, ok := source["xmux"].(map[string]interface{}); ok {
			options["reuse-settings"] = normalizeXHTTPReuseSettings(reuse)
		}
		if reuse, ok := source["reuse_settings"].(map[string]interface{}); ok {
			options["reuse-settings"] = normalizeXHTTPReuseSettings(reuse)
		}
	}

	if extra, ok := transport["extra"].(string); ok && extra != "" {
		var source map[string]interface{}
		if yaml.Unmarshal([]byte(extra), &source) == nil {
			apply(source)
		}
	}
	if extra, ok := transport["extra"].(map[string]interface{}); ok {
		apply(extra)
	}
	apply(transport)
	return options
}

func normalizeXHTTPReuseSettings(source map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range source {
		if target, ok := xhttpReuseAliases[key]; ok {
			result[target] = value
		}
	}
	return result
}
