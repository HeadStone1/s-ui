package sub

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/HeadStone1/s-ui/database/model"
	"gopkg.in/yaml.v3"
)

func TestConvertToClashMetaVLESSXHTTP(t *testing.T) {
	outbounds := []map[string]interface{}{
		{
			"type":            "vless",
			"tag":             "xhttp-node",
			"server":          "[2001:db8::1]",
			"server_port":     "443",
			"uuid":            "00000000-0000-0000-0000-000000000001",
			"packet_encoding": "xudp",
			"encryption":      "none",
			"tls": map[string]interface{}{
				"enabled":                       true,
				"server_name":                   "edge.example",
				"alpn":                          []string{"h2"},
				"xray_pinned_peer_cert_sha256":  []string{"AA11", "BB22"},
				"xray_verify_peer_cert_by_name": "cert.example,backup.example",
			},
			"transport": map[string]interface{}{
				"type": "xhttp",
				"host": "cdn.example",
				"path": "/x",
				"mode": "stream-up",
				"extra": map[string]interface{}{
					"xPaddingBytes":      "100-1000",
					"noGRPCHeader":       true,
					"scMaxEachPostBytes": 1000000,
					"xmux": map[string]interface{}{
						"maxConcurrency": "16-32",
					},
				},
			},
		},
	}

	service := ClashService{}
	result, err := service.ConvertToClashMeta(&outbounds, "rules:\n  - MATCH,Proxy\n")
	if err != nil {
		t.Fatalf("ConvertToClashMeta returned error: %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(result), &config); err != nil {
		t.Fatalf("generated invalid YAML: %v", err)
	}
	proxies, ok := config["proxies"].([]interface{})
	if !ok || len(proxies) != 1 {
		t.Fatalf("unexpected proxies: %#v", config["proxies"])
	}
	proxy := proxies[0].(map[string]interface{})
	if proxy["server"] != "2001:db8::1" || proxy["port"] != 443 {
		t.Fatalf("unexpected endpoint: %#v", proxy)
	}
	if proxy["network"] != "xhttp" || proxy["fingerprint"] != "AA11" {
		t.Fatalf("modern compatibility fields missing: %#v", proxy)
	}
	if proxy["name-cert-verify"] != "cert.example" {
		t.Fatalf("unexpected name certificate verification: %#v", proxy["name-cert-verify"])
	}
	xhttp := proxy["xhttp-opts"].(map[string]interface{})
	if xhttp["x-padding-bytes"] != "100-1000" || xhttp["no-grpc-header"] != true {
		t.Fatalf("unexpected XHTTP options: %#v", xhttp)
	}
	reuse := xhttp["reuse-settings"].(map[string]interface{})
	if reuse["max-concurrency"] != "16-32" {
		t.Fatalf("unexpected XHTTP reuse settings: %#v", reuse)
	}
}

func TestConvertToClashMetaRejectsInvalidBaseYAML(t *testing.T) {
	outbounds := []map[string]interface{}{}
	service := ClashService{}
	if _, err := service.ConvertToClashMeta(&outbounds, "rules: ["); err == nil {
		t.Fatal("expected invalid base YAML to return an error")
	}
}

func TestEnsureClashControllerSecretUsesSubscriberSecret(t *testing.T) {
	service := ClashService{}
	client := &model.Client{SubSecret: "subscriber-secret"}
	result := service.ensureClashControllerSecret("external-controller: 127.0.0.1:9090\n", client)

	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(result), &config); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("subscriber-secret"))
	if config["secret"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected controller secret: %#v", config["secret"])
	}
}

func TestRemoveUnsupportedOutbounds(t *testing.T) {
	outbounds := []map[string]interface{}{
		{
			"type":      "vless",
			"tag":       "xhttp",
			"transport": map[string]interface{}{"type": "xhttp"},
		},
		{
			"type":      "vless",
			"tag":       "ws",
			"transport": map[string]interface{}{"type": "ws"},
			"tls": map[string]interface{}{
				"enabled":                       true,
				"xray_pinned_peer_cert_sha256":  []string{"AA11"},
				"xray_verify_peer_cert_by_name": "cert.example",
			},
		},
	}
	tags := []string{"xhttp", "ws"}
	service := JsonService{}
	service.removeUnsupportedOutbounds(&outbounds, &tags)

	if len(outbounds) != 1 || len(tags) != 1 || tags[0] != "ws" {
		t.Fatalf("unexpected filtered outbounds/tags: %#v %#v", outbounds, tags)
	}
	tlsConfig := outbounds[0]["tls"].(map[string]interface{})
	if _, exists := tlsConfig["xray_pinned_peer_cert_sha256"]; exists {
		t.Fatalf("Xray-only TLS pin leaked into sing-box JSON: %#v", tlsConfig)
	}
	if _, exists := tlsConfig["xray_verify_peer_cert_by_name"]; exists {
		t.Fatalf("Xray-only TLS name leaked into sing-box JSON: %#v", tlsConfig)
	}
}
