package sub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HeadStone1/s-ui/database"
	"github.com/HeadStone1/s-ui/database/model"
	"github.com/HeadStone1/s-ui/logger"
	"github.com/op/go-logging"
	"gopkg.in/yaml.v3"
)

// TestSubscriptionProfilesWithRealCores exercises the complete subscription
// path: database -> HTTP route -> link parser -> generated profile -> real
// Mihomo/sing-box configuration validators. It is opt-in because the core
// executables are not part of the repository.
func TestSubscriptionProfilesWithRealCores(t *testing.T) {
	logger.InitLogger(logging.CRITICAL)

	mihomoBin := os.Getenv("SUI_MIHOMO_BIN")
	singBoxBin := os.Getenv("SUI_SINGBOX_BIN")
	if mihomoBin == "" || singBoxBin == "" {
		t.Skip("set SUI_MIHOMO_BIN and SUI_SINGBOX_BIN to run core validation")
	}

	tempDir := t.TempDir()
	if err := database.OpenDB(filepath.Join(tempDir, "subscription-functional.db")); err != nil {
		t.Fatalf("open functional test database: %v", err)
	}
	db := database.GetDB()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("access functional test database connection: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})
	if err := db.AutoMigrate(&model.Setting{}, &model.Tls{}, &model.Inbound{}, &model.Client{}); err != nil {
		t.Fatalf("migrate functional test database: %v", err)
	}

	settings := []model.Setting{
		{Key: "subPath", Value: "/sub/"},
		{Key: "subDomain", Value: ""},
		{Key: "subEncode", Value: "false"},
		{Key: "subShowInfo", Value: "false"},
		{Key: "subUpdates", Value: "12"},
		{Key: "subJsonExt", Value: ""},
		{Key: "subClashExt", Value: strings.TrimSpace(`
mixed-port: 17890
allow-lan: false
mode: rule
log-level: warning
external-controller: 127.0.0.1:19090
rules:
  - MATCH,Proxy
`)},
	}
	if err := db.Create(&settings).Error; err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	const (
		clientSecret = "functional-test-subscription-secret"
		clientUUID   = "00000000-0000-0000-0000-000000000001"
		certPin      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	xhttpExtra := url.QueryEscape(`{"xPaddingBytes":"100-1000","noGRPCHeader":true,"xmux":{"maxConcurrency":"16-32"}}`)
	links := []Link{
		{
			Type: "external",
			Uri: "vless://" + clientUUID + "@example.com:443" +
				"?security=tls&sni=example.com&type=ws&host=example.com&path=%2Fws" +
				"&packet-encoding=xudp&pcs=" + certPin + "&vcn=example.com#ws-node",
		},
		{
			Type: "external",
			Uri: "vless://" + clientUUID + "@example.com:443" +
				"?security=tls&sni=example.com&type=xhttp&host=example.com&path=%2Fxhttp" +
				"&mode=stream-up&encryption=none&extra=" + xhttpExtra + "#xhttp-node",
		},
	}
	linksJSON, err := json.Marshal(links)
	if err != nil {
		t.Fatal(err)
	}
	client := model.Client{
		Enable:    true,
		Name:      "functional-client",
		SubSecret: clientSecret,
		Config:    json.RawMessage(`{}`),
		Inbounds:  json.RawMessage(`[]`),
		Links:     linksJSON,
		Volume:    10 * 1024 * 1024,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("seed client: %v", err)
	}

	server := NewServer()
	engine, err := server.initRouter()
	if err != nil {
		t.Fatalf("initialize subscription router: %v", err)
	}
	basePath := "/sub/" + jsonNumber(client.Id) + "/" + clientSecret

	raw := performSubscriptionRequest(t, engine, http.MethodGet, basePath)
	if raw.Code != http.StatusOK || !strings.Contains(raw.Body.String(), "#ws-node") || !strings.Contains(raw.Body.String(), "#xhttp-node") {
		t.Fatalf("raw subscription response mismatch: status=%d body=%q", raw.Code, raw.Body.String())
	}
	assertSubscriptionHeaders(t, raw)

	head := performSubscriptionRequest(t, engine, http.MethodHead, basePath)
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD subscription response mismatch: status=%d body=%q", head.Code, head.Body.String())
	}
	assertSubscriptionHeaders(t, head)

	badSecret := performSubscriptionRequest(t, engine, http.MethodGet, "/sub/"+jsonNumber(client.Id)+"/wrong-secret")
	if badSecret.Code != http.StatusBadRequest {
		t.Fatalf("wrong subscription secret returned %d, want 400", badSecret.Code)
	}
	legacyRoute := performSubscriptionRequest(t, engine, http.MethodGet, "/sub/"+client.Name)
	if legacyRoute.Code != http.StatusNotFound {
		t.Fatalf("legacy name-only subscription route returned %d, want 404", legacyRoute.Code)
	}

	clash := performSubscriptionRequest(t, engine, http.MethodGet, basePath+"?format=clash")
	if clash.Code != http.StatusOK {
		t.Fatalf("Clash subscription returned %d: %s", clash.Code, clash.Body.String())
	}
	clashBody := clash.Body.String()
	if !strings.Contains(clashBody, "network: xhttp") || !strings.Contains(clashBody, "xhttp-opts:") || !strings.Contains(clashBody, "network: ws") {
		t.Fatalf("Clash profile is missing WS/XHTTP proxies:\n%s", clashBody)
	}
	var clashConfig map[string]interface{}
	if err := yaml.Unmarshal([]byte(clashBody), &clashConfig); err != nil {
		t.Fatalf("decode generated Clash profile: %v", err)
	}
	digest := sha256.Sum256([]byte(clientSecret))
	if clashConfig["secret"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("generated controller secret does not match the derived subscription secret")
	}
	clashPath := filepath.Join(tempDir, "clash.yaml")
	if err := os.WriteFile(clashPath, []byte(clashBody), 0600); err != nil {
		t.Fatalf("write generated Clash profile: %v", err)
	}
	assertCoreAccepts(t, mihomoBin, "Mihomo", "-t", "-f", clashPath, "-d", filepath.Join(tempDir, "mihomo-home"))

	singBox := performSubscriptionRequest(t, engine, http.MethodGet, basePath+"?format=json")
	if singBox.Code != http.StatusOK {
		t.Fatalf("sing-box subscription returned %d: %s", singBox.Code, singBox.Body.String())
	}
	singBoxBody := singBox.Body.String()
	if strings.Contains(singBoxBody, `"type": "xhttp"`) || strings.Contains(singBoxBody, "xray_pinned_peer_cert_sha256") || strings.Contains(singBoxBody, "xray_verify_peer_cert_by_name") {
		t.Fatalf("sing-box profile contains Xray/Mihomo-only fields:\n%s", singBoxBody)
	}
	if !strings.Contains(singBoxBody, `"type": "ws"`) || !strings.Contains(singBoxBody, `"tag": "1.ws-node"`) {
		t.Fatalf("sing-box profile is missing the supported WS proxy:\n%s", singBoxBody)
	}
	singBoxPath := filepath.Join(tempDir, "sing-box.json")
	if err := os.WriteFile(singBoxPath, []byte(singBoxBody), 0600); err != nil {
		t.Fatalf("write generated sing-box profile: %v", err)
	}
	assertCoreAccepts(t, singBoxBin, "sing-box", "check", "-c", singBoxPath, "-D", filepath.Join(tempDir, "sing-box-home"))
}

func performSubscriptionRequest(t *testing.T, handler http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertSubscriptionHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Subscription-Userinfo") == "" || response.Header().Get("Profile-Update-Interval") != "12" || response.Header().Get("Profile-Title") == "" {
		t.Fatalf("subscription headers missing or invalid: %#v", response.Header())
	}
}

func assertCoreAccepts(t *testing.T, binary, name string, args ...string) {
	t.Helper()
	if err := os.MkdirAll(args[len(args)-1], 0700); err != nil {
		t.Fatalf("create %s working directory: %v", name, err)
	}
	command := exec.Command(binary, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s rejected generated configuration: %v\n%s", name, err, output)
	}
	t.Logf("%s accepted generated configuration: %s", name, strings.TrimSpace(string(output)))
}

func jsonNumber(value uint) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
