package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/HeadStone1/s-ui/database/model"
	"github.com/HeadStone1/s-ui/util/common"
)

var InboundTypeWithLink = []string{"socks", "http", "mixed", "shadowsocks", "naive", "hysteria", "hysteria2", "anytls", "tuic", "vless", "trojan", "vmess"}

type LinkParam struct {
	Key   string
	Value string
}

func LinkGenerator(clientConfig json.RawMessage, i *model.Inbound, hostname string) []string {
	inbound, err := i.MarshalFull()
	if err != nil {
		return []string{}
	}

	var tls map[string]interface{}
	if i.TlsId > 0 {
		tls = prepareTls(i.Tls)
	}

	var userConfig map[string]map[string]interface{}
	if err := json.Unmarshal(clientConfig, &userConfig); err != nil {
		return []string{}
	}

	var Addrs []map[string]interface{}
	if err := json.Unmarshal(i.Addrs, &Addrs); err != nil {
		return []string{}
	}
	if len(Addrs) == 0 {
		Addrs = append(Addrs, map[string]interface{}{
			"server":      hostname,
			"server_port": (*inbound)["listen_port"],
			"remark":      i.Tag,
		})
		if i.TlsId > 0 {
			Addrs[0]["tls"] = tls
		}
	} else {
		for index, addr := range Addrs {
			addrRemark, _ := addr["remark"].(string)
			Addrs[index]["remark"] = i.Tag + addrRemark
			if i.TlsId > 0 {
				newTls := map[string]interface{}{}
				for k, v := range tls {
					newTls[k] = v
				}

				// Override tls
				if addrTls, ok := addr["tls"].(map[string]interface{}); ok {
					for k, v := range addrTls {
						newTls[k] = v
					}
				}
				Addrs[index]["tls"] = newTls
			}
		}
	}

	switch i.Type {
	case "socks":
		return socksLink(userConfig["socks"], Addrs)
	case "http":
		return httpLink(userConfig["http"], Addrs)
	case "mixed":
		return append(
			socksLink(userConfig["socks"], Addrs),
			httpLink(userConfig["http"], Addrs)...,
		)
	case "shadowsocks":
		return shadowsocksLink(userConfig, *inbound, Addrs)
	case "naive":
		return naiveLink(userConfig["naive"], *inbound, Addrs)
	case "hysteria":
		return hysteriaLink(userConfig["hysteria"], *inbound, Addrs)
	case "hysteria2":
		return hysteria2Link(userConfig["hysteria2"], *inbound, Addrs)
	case "tuic":
		return tuicLink(userConfig["tuic"], *inbound, Addrs)
	case "vless":
		return vlessLink(userConfig["vless"], *inbound, Addrs)
	case "anytls":
		return anytlsLink(userConfig["anytls"], Addrs)
	case "trojan":
		return trojanLink(userConfig["trojan"], *inbound, Addrs)
	case "vmess":
		return vmessLink(userConfig["vmess"], *inbound, Addrs)
	}

	return []string{}
}

func prepareTls(t *model.Tls) map[string]interface{} {
	var iTls, oTls map[string]interface{}
	if err := json.Unmarshal(t.Client, &oTls); err != nil {
		return nil
	}
	if err := json.Unmarshal(t.Server, &iTls); err != nil {
		return nil
	}

	for k, v := range iTls {
		switch k {
		case "enabled", "server_name", "alpn":
			oTls[k] = v
		case "reality":
			reality, _ := v.(map[string]interface{})
			clientReality, _ := oTls["reality"].(map[string]interface{})
			if clientReality == nil {
				clientReality = make(map[string]interface{})
			}
			clientReality["enabled"] = reality["enabled"]
			if shortIDs, hasSIds := reality["short_id"].([]interface{}); hasSIds && len(shortIDs) > 0 {
				clientReality["short_id"] = shortIDs[common.RandomInt(len(shortIDs))]
			}
			oTls["reality"] = clientReality
		}
	}
	if boolValue(oTls["insecure"]) && stringListValue(oTls["xray_pinned_peer_cert_sha256"]) == "" {
		if fingerprint := certificateSHA256FromTLSConfig(iTls); fingerprint != "" {
			oTls["xray_pinned_peer_cert_sha256"] = []string{fingerprint}
		}
	}
	return oTls
}

func certificateSHA256FromTLSConfig(tlsConfig map[string]interface{}) string {
	var certificatePEM []byte
	switch certificate := tlsConfig["certificate"].(type) {
	case string:
		certificatePEM = []byte(certificate)
	case []string:
		certificatePEM = []byte(strings.Join(certificate, "\n"))
	case []interface{}:
		certificatePEM = []byte(strings.Join(stringSliceValue(certificate), "\n"))
	}
	if len(certificatePEM) == 0 {
		if certificatePath, ok := tlsConfig["certificate_path"].(string); ok && certificatePath != "" {
			certificatePEM, _ = os.ReadFile(certificatePath)
		}
	}
	for len(certificatePEM) > 0 {
		block, rest := pem.Decode(certificatePEM)
		if block == nil {
			return ""
		}
		if block.Type == "CERTIFICATE" {
			digest := sha256.Sum256(block.Bytes)
			return hex.EncodeToString(digest[:])
		}
		certificatePEM = rest
	}
	return ""
}

func socksLink(userConfig map[string]interface{}, addrs []map[string]interface{}) []string {
	var links []string
	for _, addr := range addrs {
		links = append(links, fmt.Sprintf("socks5://%s:%s@%s:%d", userConfig["username"], userConfig["password"], formatLinkHost(addr["server"].(string)), uint(addr["server_port"].(float64))))
	}
	return links
}

func httpLink(userConfig map[string]interface{}, addrs []map[string]interface{}) []string {
	var links []string
	protocol := "http"
	for _, addr := range addrs {
		if addr["tls"] != nil {
			protocol = "https"
		}
		links = append(links, fmt.Sprintf("%s://%s:%s@%s:%d", protocol, userConfig["username"], userConfig["password"], formatLinkHost(addr["server"].(string)), uint(addr["server_port"].(float64))))
	}
	return links
}

func shadowsocksLink(
	userConfig map[string]map[string]interface{},
	inbound map[string]interface{},
	addrs []map[string]interface{}) []string {

	var userPass []string
	method, _ := inbound["method"].(string)
	if strings.HasPrefix(method, "2022") {
		inbPass, _ := inbound["password"].(string)
		userPass = append(userPass, inbPass)
	}
	var pass string
	if method == "2022-blake3-aes-128-gcm" {
		pass, _ = userConfig["shadowsocks16"]["password"].(string)
	} else {
		pass, _ = userConfig["shadowsocks"]["password"].(string)
	}
	userPass = append(userPass, pass)

	uriBase := fmt.Sprintf("ss://%s", toBase64([]byte(fmt.Sprintf("%s:%s", method, strings.Join(userPass, ":")))))

	var links []string
	for _, addr := range addrs {
		port, _ := addr["server_port"].(float64)
		links = append(links, fmt.Sprintf("%s@%s:%.0f#%s", uriBase, formatLinkHost(addr["server"].(string)), port, addr["remark"].(string)))
	}
	return links
}

func naiveLink(
	userConfig map[string]interface{},
	inbound map[string]interface{},
	addrs []map[string]interface{}) []string {

	password, _ := userConfig["password"].(string)
	username, _ := userConfig["username"].(string)

	baseUri := "http2://"
	var links []string

	for _, addr := range addrs {
		var params []LinkParam
		params = append(params, LinkParam{"padding", "1"})
		if tls, ok := addr["tls"].(map[string]interface{}); ok {
			if sni, ok := tls["server_name"].(string); ok {
				params = append(params, LinkParam{"peer", sni})
			}
			if alpn, ok := tls["alpn"].([]interface{}); ok {
				alpnList := make([]string, len(alpn))
				for i, v := range alpn {
					alpnList[i] = v.(string)
				}
				params = append(params, LinkParam{"alpn", strings.Join(alpnList, ",")})
			}
			if insecure, ok := tls["insecure"].(bool); ok && insecure {
				params = append(params, LinkParam{"insecure", "1"})
			}
		}
		if tfo, ok := inbound["tcp_fast_open"].(bool); ok && tfo {
			params = append(params, LinkParam{"tfo", "1"})
		} else {
			params = append(params, LinkParam{"tfo", "0"})
		}

		port, _ := addr["server_port"].(float64)
		uri := baseUri + toBase64([]byte(fmt.Sprintf("%s:%s@%s:%.0f", username, password, formatLinkHost(addr["server"].(string)), port)))
		links = append(links, addParams(uri, params, addr["remark"].(string)))
	}
	return links
}

func hysteriaLink(
	userConfig map[string]interface{},
	inbound map[string]interface{},
	addrs []map[string]interface{}) []string {

	baseUri := "hysteria://"
	var links []string

	for _, addr := range addrs {
		var params []LinkParam
		if upmbps, ok := inbound["up_mbps"].(float64); ok {
			params = append(params, LinkParam{"downmbps", fmt.Sprintf("%.0f", upmbps)})
		}
		if downmbps, ok := inbound["down_mbps"].(float64); ok {
			params = append(params, LinkParam{"upmbps", fmt.Sprintf("%.0f", downmbps)})
		}
		if auth, ok := userConfig["auth_str"].(string); ok {
			params = append(params, LinkParam{"auth", auth})
		}
		if tls, ok := addr["tls"].(map[string]interface{}); ok {
			getTlsParams(&params, tls, "insecure")
		}
		if obfs, ok := inbound["obfs"].(string); ok {
			params = append(params, LinkParam{"obfs", obfs})
		}
		if tfo, ok := inbound["tcp_fast_open"].(bool); ok && tfo {
			params = append(params, LinkParam{"fastopen", "1"})
		} else {
			params = append(params, LinkParam{"fastopen", "0"})
		}
		var outJson map[string]interface{}
		if err := json.Unmarshal(inbound["out_json"].(json.RawMessage), &outJson); err != nil {
			return []string{} // Handle error
		}
		if mport, ok := outJson["server_ports"].([]interface{}); ok {
			mportList := make([]string, len(mport))
			for i, v := range mport {
				mportList[i] = v.(string)
			}
			params = append(params, LinkParam{"mport", strings.Join(mportList, ",")})
		}

		port, _ := addr["server_port"].(float64)
		uri := fmt.Sprintf("%s%s:%.0f", baseUri, formatLinkHost(addr["server"].(string)), port)
		links = append(links, addParams(uri, params, addr["remark"].(string)))
	}

	return links
}

func hysteria2Link(
	userConfig map[string]interface{},
	inbound map[string]interface{},
	addrs []map[string]interface{}) []string {

	password, _ := userConfig["password"].(string)
	baseUri := fmt.Sprintf("%s%s@", "hysteria2://", password)
	var links []string

	for _, addr := range addrs {
		var params []LinkParam
		if upmbps, ok := inbound["up_mbps"].(float64); ok {
			params = append(params, LinkParam{"downmbps", fmt.Sprintf("%.0f", upmbps)})
		}
		if downmbps, ok := inbound["down_mbps"].(float64); ok {
			params = append(params, LinkParam{"upmbps", fmt.Sprintf("%.0f", downmbps)})
		}
		if tls, ok := addr["tls"].(map[string]interface{}); ok {
			getTlsParams(&params, tls, "insecure")
		}
		if obfs, ok := inbound["obfs"].(map[string]interface{}); ok {
			if obfsType, ok := obfs["type"].(string); ok {
				params = append(params, LinkParam{"obfs", obfsType})
			}
			if obfsPassword, ok := obfs["password"].(string); ok {
				params = append(params, LinkParam{"obfs-password", obfsPassword})
			}
		}
		if tfo, ok := inbound["tcp_fast_open"].(bool); ok && tfo {
			params = append(params, LinkParam{"fastopen", "1"})
		} else {
			params = append(params, LinkParam{"fastopen", "0"})
		}
		var outJson map[string]interface{}
		if err := json.Unmarshal(inbound["out_json"].(json.RawMessage), &outJson); err != nil {
			return []string{} // Handle error
		}
		if mport, ok := outJson["server_ports"].([]interface{}); ok {
			mportList := make([]string, len(mport))
			for i, v := range mport {
				mportList[i] = v.(string)
			}
			params = append(params, LinkParam{"mport", strings.Join(mportList, ",")})
		}

		port, _ := addr["server_port"].(float64)
		uri := fmt.Sprintf("%s%s:%.0f", baseUri, formatLinkHost(addr["server"].(string)), port)
		links = append(links, addParams(uri, params, addr["remark"].(string)))
	}

	return links
}

func anytlsLink(
	userConfig map[string]interface{},
	addrs []map[string]interface{}) []string {

	password, _ := userConfig["password"].(string)
	baseUri := fmt.Sprintf("%s%s@", "anytls://", password)
	var links []string

	for _, addr := range addrs {
		var params []LinkParam
		if tls, ok := addr["tls"].(map[string]interface{}); ok {
			getTlsParams(&params, tls, "insecure")
		}

		port, _ := addr["server_port"].(float64)
		uri := fmt.Sprintf("%s%s:%.0f", baseUri, formatLinkHost(addr["server"].(string)), port)
		links = append(links, addParams(uri, params, addr["remark"].(string)))
	}

	return links
}

func tuicLink(
	userConfig map[string]interface{},
	inbound map[string]interface{},
	addrs []map[string]interface{}) []string {

	password, _ := userConfig["password"].(string)
	uuid, _ := userConfig["uuid"].(string)
	baseUri := fmt.Sprintf("%s%s:%s@", "tuic://", uuid, password)
	var links []string

	for _, addr := range addrs {
		var params []LinkParam
		if tls, ok := addr["tls"].(map[string]interface{}); ok {
			getTlsParams(&params, tls, "insecure")
		}
		if congestionControl, ok := inbound["congestion_control"].(string); ok {
			params = append(params, LinkParam{"congestion_control", congestionControl})
		}

		port, _ := addr["server_port"].(float64)
		uri := fmt.Sprintf("%s%s:%.0f", baseUri, formatLinkHost(addr["server"].(string)), port)
		links = append(links, addParams(uri, params, addr["remark"].(string)))
	}

	return links
}

func vlessLink(
	userConfig map[string]interface{},
	inbound map[string]interface{},
	addrs []map[string]interface{}) []string {

	uuid, _ := userConfig["uuid"].(string)
	baseParams := getTransportParams(inbound["transport"])
	var links []string

	for _, addr := range addrs {
		params := make([]LinkParam, len(baseParams))
		copy(params, baseParams)
		if tls, ok := addr["tls"].(map[string]interface{}); ok && boolValue(tls["enabled"]) {
			getTlsParams(&params, tls, "allowInsecure")
			if flow, ok := userConfig["flow"].(string); ok {
				params = append(params, LinkParam{"flow", flow})
			}
		}
		if packetEncoding, ok := userConfig["packet_encoding"].(string); ok && packetEncoding != "" {
			params = append(params, LinkParam{"packet-encoding", packetEncoding})
		}
		if encryption, ok := userConfig["encryption"].(string); ok && encryption != "" {
			params = append(params, LinkParam{"encryption", encryption})
		}
		port, _ := addr["server_port"].(float64)
		uri := fmt.Sprintf("vless://%s@%s:%.0f", uuid, formatLinkHost(addr["server"].(string)), port)
		uri = addParams(uri, params, addr["remark"].(string))
		links = append(links, uri)
	}

	return links
}

func trojanLink(
	userConfig map[string]interface{},
	inbound map[string]interface{},
	addrs []map[string]interface{}) []string {
	password, _ := userConfig["password"].(string)
	baseParams := getTransportParams(inbound["transport"])
	var links []string

	for _, addr := range addrs {
		params := make([]LinkParam, len(baseParams))
		copy(params, baseParams)
		if tls, ok := addr["tls"].(map[string]interface{}); ok && boolValue(tls["enabled"]) {
			getTlsParams(&params, tls, "allowInsecure")
		}
		port, _ := addr["server_port"].(float64)
		uri := fmt.Sprintf("trojan://%s@%s:%.0f", password, formatLinkHost(addr["server"].(string)), port)
		uri = addParams(uri, params, addr["remark"].(string))
		links = append(links, uri)
	}

	return links
}

func vmessLink(
	userConfig map[string]interface{},
	inbound map[string]interface{},
	addrs []map[string]interface{}) []string {

	uuid, _ := userConfig["uuid"].(string)
	transportParams := getTransportParams(inbound["transport"])
	var links []string

	baseParams := map[string]interface{}{
		"v":   "2",
		"id":  uuid,
		"aid": 0,
	}

	var net, typ, host, path string
	for _, p := range transportParams {
		switch p.Key {
		case "type":
			net = p.Value
		case "host":
			host = p.Value
		case "path":
			path = p.Value
		}
	}

	if net == "http" || net == "tcp" {
		baseParams["net"] = "tcp"
		if net == "http" {
			typ = "http"
		}
	} else {
		baseParams["net"] = net
	}

	for _, addr := range addrs {
		obj := make(map[string]interface{})
		for k, v := range baseParams {
			obj[k] = v
		}

		obj["add"], _ = addr["server"].(string)
		port, _ := addr["server_port"].(float64)
		obj["port"] = fmt.Sprintf("%.0f", port)
		obj["ps"], _ = addr["remark"].(string)
		if typ != "" {
			obj["type"] = typ
		}
		if host != "" {
			obj["host"] = host
		}
		if path != "" {
			obj["path"] = path
		}
		if packetEncoding, ok := userConfig["packet_encoding"].(string); ok && packetEncoding != "" {
			obj["packet-encoding"] = packetEncoding
		}
		if globalPadding, ok := userConfig["global_padding"].(bool); ok {
			obj["global-padding"] = globalPadding
		}
		if authenticatedLength, ok := userConfig["authenticated_length"].(bool); ok {
			obj["authenticated-length"] = authenticatedLength
		}
		populateVmessTlsParams(obj, addr["tls"])

		jsonStr, _ := json.Marshal(obj)

		uri := fmt.Sprintf("vmess://%s", toBase64(jsonStr))
		links = append(links, uri)
	}
	return links
}

func populateVmessTlsParams(obj map[string]interface{}, tlsConfig interface{}) {
	if tlsMap, ok := tlsConfig.(map[string]interface{}); ok && boolValue(tlsMap["enabled"]) {
		obj["tls"] = "tls"
		if boolValue(tlsMap["insecure"]) && stringListValue(tlsMap["xray_pinned_peer_cert_sha256"]) == "" {
			// v2rayN's current Base64-JSON format uses "insecure" rather
			// than the deprecated Xray allowInsecure field.
			obj["insecure"] = "1"
		}
		var tlsParams []LinkParam
		getTlsParams(&tlsParams, tlsMap, "allowInsecure")
		for _, p := range tlsParams {
			switch p.Key {
			case "security":
				// ignore, as "tls" is already set
			case "pcs":
				obj["pcs"] = p.Value
			case "vcn":
				obj["vcn"] = p.Value
			case "sni":
				obj["sni"] = p.Value
			case "fp":
				obj["fp"] = p.Value
			case "alpn":
				obj["alpn"] = p.Value
			}
		}
	} else {
		obj["tls"] = "none"
	}
}

func toBase64(d []byte) string {
	return base64.StdEncoding.EncodeToString(d)
}

func addParams(uri string, params []LinkParam, remark string) string {
	URL, _ := url.Parse(uri)
	var q []string
	for _, p := range params {
		switch p.Key {
		case "mport", "alpn":
			q = append(q, fmt.Sprintf("%s=%s", p.Key, p.Value))
		default:
			q = append(q, fmt.Sprintf("%s=%s", p.Key, url.QueryEscape(p.Value)))
		}
	}
	URL.RawQuery = strings.Join(q, "&")
	URL.Fragment = remark
	return URL.String()
}

func getTransportParams(t interface{}) []LinkParam {
	var params []LinkParam
	trasport, _ := t.(map[string]interface{})
	var transportType string
	if tt, ok := trasport["type"].(string); ok {
		transportType = tt
	} else {
		transportType = "tcp"
	}
	params = append(params, LinkParam{"type", transportType})
	if transportType == "tcp" {
		return params
	}

	switch transportType {
	case "http":
		if hosts := stringSliceValue(trasport["host"]); len(hosts) > 0 {
			params = append(params, LinkParam{"host", strings.Join(hosts, ",")})
		}
		if path, ok := trasport["path"].(string); ok {
			params = append(params, LinkParam{"path", path})
		}
	case "ws":
		if path, ok := trasport["path"].(string); ok {
			params = append(params, LinkParam{"path", path})
		}
		if headers, ok := trasport["headers"].(map[string]interface{}); ok {
			if host, ok := headers["Host"].(string); ok {
				params = append(params, LinkParam{"host", host})
			}
		}
	case "grpc":
		if serviceName, ok := trasport["service_name"].(string); ok {
			params = append(params, LinkParam{"serviceName", serviceName})
		}
	case "httpupgrade":
		if host, ok := trasport["host"].(string); ok {
			params = append(params, LinkParam{"host", host})
		}
		if path, ok := trasport["path"].(string); ok {
			params = append(params, LinkParam{"path", path})
		}
	case "xhttp":
		if host, ok := trasport["host"].(string); ok && host != "" {
			params = append(params, LinkParam{"host", host})
		}
		if path, ok := trasport["path"].(string); ok && path != "" {
			params = append(params, LinkParam{"path", path})
		}
		if mode, ok := trasport["mode"].(string); ok && mode != "" {
			params = append(params, LinkParam{"mode", mode})
		}
		if extra := xhttpExtraJSON(trasport); extra != "" {
			params = append(params, LinkParam{"extra", extra})
		}
	}
	return params
}

func getTlsParams(params *[]LinkParam, tls map[string]interface{}, insecureKey string) {
	reality, hasReality := tls["reality"].(map[string]interface{})
	if hasReality && boolValue(reality["enabled"]) {
		*params = append(*params, LinkParam{"security", "reality"})
		if pbk, ok := reality["public_key"].(string); ok {
			*params = append(*params, LinkParam{"pbk", pbk})
		}
		if sid, ok := reality["short_id"].(string); ok {
			*params = append(*params, LinkParam{"sid", sid})
		}
	} else {
		*params = append(*params, LinkParam{"security", "tls"})
		pcs := stringListValue(tls["xray_pinned_peer_cert_sha256"])
		if pcs != "" {
			*params = append(*params, LinkParam{"pcs", pcs})
		}
		if vcn := stringValue(tls["xray_verify_peer_cert_by_name"]); vcn != "" {
			*params = append(*params, LinkParam{"vcn", vcn})
		}
		if boolValue(tls["insecure"]) {
			if insecureKey != "allowInsecure" {
				*params = append(*params, LinkParam{insecureKey, "1"})
			} else if pcs == "" {
				// Older clients still need this fallback for self-signed
				// deployments when no certificate pin is available.
				*params = append(*params, LinkParam{"allowInsecure", "1"})
			}
		}
		if disableSni, ok := tls["disable_sni"].(bool); ok && disableSni {
			*params = append(*params, LinkParam{"disable_sni", "1"})
		}
	}
	if utls, ok := tls["utls"].(map[string]interface{}); ok {
		if fingerprint, ok := utls["fingerprint"].(string); ok {
			*params = append(*params, LinkParam{"fp", fingerprint})
		}
	}
	if sni, ok := tls["server_name"].(string); ok {
		*params = append(*params, LinkParam{"sni", sni})
	}
	if alpnList := stringSliceValue(tls["alpn"]); len(alpnList) > 0 {
		*params = append(*params, LinkParam{"alpn", strings.Join(alpnList, ",")})
	}
}

func stringValue(value interface{}) string {
	valueString, _ := value.(string)
	return valueString
}

func stringListValue(value interface{}) string {
	switch values := value.(type) {
	case string:
		return values
	case []string:
		return strings.Join(values, ",")
	case []interface{}:
		result := make([]string, 0, len(values))
		for _, item := range values {
			if itemString, ok := item.(string); ok {
				result = append(result, itemString)
			}
		}
		return strings.Join(result, ",")
	default:
		return ""
	}
}

func stringSliceValue(value interface{}) []string {
	switch values := value.(type) {
	case string:
		if values == "" {
			return nil
		}
		return []string{values}
	case []string:
		return values
	case []interface{}:
		result := make([]string, 0, len(values))
		for _, item := range values {
			if itemString, ok := item.(string); ok {
				result = append(result, itemString)
			}
		}
		return result
	default:
		return nil
	}
}

func boolValue(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed == "1" || strings.EqualFold(typed, "true")
	case float64:
		return typed != 0
	case int:
		return typed != 0
	default:
		return false
	}
}

func formatLinkHost(host string) string {
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func xhttpExtraJSON(transport map[string]interface{}) string {
	if extra, ok := transport["extra"].(string); ok && extra != "" {
		return extra
	}
	if extra, ok := transport["extra"].(map[string]interface{}); ok && len(extra) > 0 {
		if encoded, err := json.Marshal(extra); err == nil {
			return string(encoded)
		}
	}

	extra := make(map[string]interface{})
	for key, value := range transport {
		if key == "type" || key == "host" || key == "path" || key == "mode" || key == "extra" {
			continue
		}
		extra[xhttpXrayKey(key)] = value
	}
	if len(extra) == 0 {
		return ""
	}
	encoded, err := json.Marshal(extra)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func xhttpXrayKey(key string) string {
	if key == "no_grpc_header" {
		return "noGRPCHeader"
	}
	parts := strings.Split(key, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}
