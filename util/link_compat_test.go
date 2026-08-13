package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/HeadStone1/s-ui/database/model"
)

func TestGetOutboundVLESSXHTTPWithModernTLSFields(t *testing.T) {
	extra := url.QueryEscape(`{"xPaddingBytes":"100-1000","noGRPCHeader":true,"xmux":{"maxConcurrency":"16-32"}}`)
	link := "vless://00000000-0000-0000-0000-000000000001@[2001:db8::1]:443" +
		"?security=tls&sni=edge.example&pcs=AA11%2CBB22&vcn=cert.example" +
		"&type=xhttp&host=cdn.example&path=%2Fx&mode=stream-up&extra=" + extra +
		"&packet-encoding=xudp&encryption=none#node"

	outbound, tag, err := GetOutbound(link, 0)
	if err != nil {
		t.Fatalf("GetOutbound returned error: %v", err)
	}
	if tag != "node" {
		t.Fatalf("unexpected tag: %q", tag)
	}
	if got := (*outbound)["server"]; got != "2001:db8::1" {
		t.Fatalf("unexpected IPv6 server: %#v", got)
	}
	if got := (*outbound)["packet_encoding"]; got != "xudp" {
		t.Fatalf("packet encoding was not preserved: %#v", got)
	}

	tlsConfig := mustMap(t, (*outbound)["tls"])
	if got := tlsConfig["xray_verify_peer_cert_by_name"]; got != "cert.example" {
		t.Fatalf("unexpected vcn: %#v", got)
	}
	pins := stringSliceValue(tlsConfig["xray_pinned_peer_cert_sha256"])
	if len(pins) != 2 || pins[0] != "AA11" || pins[1] != "BB22" {
		t.Fatalf("unexpected pcs list: %#v", pins)
	}

	transport := mustMap(t, (*outbound)["transport"])
	if transport["type"] != "xhttp" || transport["mode"] != "stream-up" {
		t.Fatalf("unexpected XHTTP transport: %#v", transport)
	}
	if transport["xPaddingBytes"] != "100-1000" || transport["noGRPCHeader"] != true {
		t.Fatalf("XHTTP extra was not decoded: %#v", transport)
	}
}

func TestVMessModernTLSDoesNotTreatFalseAsInsecure(t *testing.T) {
	payload := map[string]interface{}{
		"v":             "2",
		"ps":            "node",
		"add":           "example.com",
		"port":          "443",
		"id":            "00000000-0000-0000-0000-000000000001",
		"aid":           "0",
		"scy":           "auto",
		"net":           "ws",
		"path":          "/ws",
		"tls":           "tls",
		"insecure":      "0",
		"allowInsecure": false,
		"pcs":           "AA11,BB22",
		"vcn":           "cert.example",
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	outbound, _, err := GetOutbound("vmess://"+base64.StdEncoding.EncodeToString(encoded), 0)
	if err != nil {
		t.Fatalf("GetOutbound returned error: %v", err)
	}
	tlsConfig := mustMap(t, (*outbound)["tls"])
	if boolValue(tlsConfig["insecure"]) {
		t.Fatalf("false insecure flags were treated as true: %#v", tlsConfig)
	}
	if (*outbound)["server_port"] != 443 || (*outbound)["security"] != "auto" {
		t.Fatalf("numeric/string VMess fields were not normalized: %#v", *outbound)
	}
	if pins := stringSliceValue(tlsConfig["xray_pinned_peer_cert_sha256"]); len(pins) != 2 {
		t.Fatalf("pcs list was not parsed: %#v", pins)
	}
}

func TestGetOutboundModernVMessAEADURI(t *testing.T) {
	link := "vmess://00000000-0000-0000-0000-000000000001@example.com:443" +
		"?type=ws&host=cdn.example&path=%2Fws&security=tls&sni=edge.example" +
		"&encryption=none&pcs=AA11&vcn=cert.example#modern"

	outbound, tag, err := GetOutbound(link, 0)
	if err != nil {
		t.Fatalf("GetOutbound returned error: %v", err)
	}
	if tag != "modern" || (*outbound)["security"] != "none" {
		t.Fatalf("unexpected modern VMess outbound: %#v", *outbound)
	}
	transport := mustMap(t, (*outbound)["transport"])
	if transport["type"] != "ws" || transport["path"] != "/ws" {
		t.Fatalf("unexpected modern VMess transport: %#v", transport)
	}
	tlsConfig := mustMap(t, (*outbound)["tls"])
	if tlsConfig["xray_verify_peer_cert_by_name"] != "cert.example" {
		t.Fatalf("modern VMess TLS fields missing: %#v", tlsConfig)
	}
}

func TestModernXrayTLSLinkParamsOmitAllowInsecure(t *testing.T) {
	params := make([]LinkParam, 0)
	getTlsParams(&params, map[string]interface{}{
		"enabled":                       true,
		"insecure":                      true,
		"server_name":                   "edge.example",
		"xray_pinned_peer_cert_sha256":  []string{"AA11", "BB22"},
		"xray_verify_peer_cert_by_name": "cert.example",
	}, "allowInsecure")

	values := linkParamMap(params)
	if values["pcs"] != "AA11,BB22" || values["vcn"] != "cert.example" {
		t.Fatalf("modern TLS params missing: %#v", values)
	}
	if _, exists := values["allowInsecure"]; exists {
		t.Fatalf("deprecated allowInsecure was emitted: %#v", values)
	}
}

func TestLegacyInsecureFallbackWithoutCertificatePin(t *testing.T) {
	params := make([]LinkParam, 0)
	getTlsParams(&params, map[string]interface{}{
		"enabled":  true,
		"insecure": true,
	}, "allowInsecure")

	values := linkParamMap(params)
	if values["allowInsecure"] != "1" {
		t.Fatalf("legacy self-signed fallback missing: %#v", values)
	}
}

func TestPrepareTLSAddsCertificatePinForSelfSignedServer(t *testing.T) {
	der := []byte{1, 2, 3, 4, 5}
	pemData := "-----BEGIN CERTIFICATE-----\n" +
		base64.StdEncoding.EncodeToString(der) +
		"\n-----END CERTIFICATE-----"
	server, _ := json.Marshal(map[string]interface{}{
		"enabled":     true,
		"certificate": strings.Split(pemData, "\n"),
	})
	client, _ := json.Marshal(map[string]interface{}{
		"insecure": true,
	})

	prepared := prepareTls(&model.Tls{Server: server, Client: client})
	pins := stringSliceValue(prepared["xray_pinned_peer_cert_sha256"])
	digest := sha256.Sum256(der)
	expected := hex.EncodeToString(digest[:])
	if len(pins) != 1 || pins[0] != expected {
		t.Fatalf("unexpected generated certificate pin: %#v", pins)
	}
}

func TestXHTTPExtraJSONAndIPv6Host(t *testing.T) {
	transport := map[string]interface{}{
		"type":                   "xhttp",
		"host":                   "cdn.example",
		"path":                   "/x",
		"mode":                   "packet-up",
		"x_padding_bytes":        "100-1000",
		"no_grpc_header":         true,
		"sc_max_each_post_bytes": 1000000,
	}
	params := linkParamMap(getTransportParams(transport))
	if params["type"] != "xhttp" || params["host"] != "cdn.example" {
		t.Fatalf("unexpected XHTTP params: %#v", params)
	}
	var extra map[string]interface{}
	if err := json.Unmarshal([]byte(params["extra"]), &extra); err != nil {
		t.Fatalf("invalid XHTTP extra JSON: %v", err)
	}
	if extra["xPaddingBytes"] != "100-1000" || extra["noGRPCHeader"] != true {
		t.Fatalf("unexpected XHTTP extra: %#v", extra)
	}
	if got := formatLinkHost("2001:db8::1"); got != "[2001:db8::1]" {
		t.Fatalf("unexpected IPv6 link host: %q", got)
	}
	if got := formatLinkHost("[2001:db8::1]"); strings.Count(got, "[") != 1 {
		t.Fatalf("already bracketed IPv6 host changed incorrectly: %q", got)
	}
}

func mustMap(t *testing.T, value interface{}) map[string]interface{} {
	t.Helper()
	result, ok := value.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", value)
	}
	return result
}

func linkParamMap(params []LinkParam) map[string]string {
	result := make(map[string]string, len(params))
	for _, param := range params {
		result[param.Key] = param.Value
	}
	return result
}
