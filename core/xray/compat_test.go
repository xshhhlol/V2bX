package xray

import (
	"encoding/json"
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func TestXrayCompatibilitySessionAliases(t *testing.T) {
	for _, input := range []string{
		`{"path":"/test","sessionPlacement":"header","sessionKey":"X-Session-Test"}`,
		`{"path":"/test","extra":{"sessionPlacement":"header","sessionKey":"X-Session-Test"}}`,
		`{"path":"/test","sessionPlacement":"cookie","sessionIDPlacement":"header","sessionKey":"old","sessionIDKey":"X-Session-Test"}`,
	} {
		data, err := normalizeXHTTPSettings(json.RawMessage(input))
		if err != nil {
			t.Fatal(err)
		}
		var config coreConf.SplitHTTPConfig
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil {
			t.Fatal(err)
		}
		transport := built.(*splithttp.Config)
		if transport.SessionIDPlacement != "header" || transport.SessionIDKey != "X-Session-Test" || transport.Path != "/test" {
			t.Fatalf("legacy settings changed: %+v", transport)
		}
	}
}

func TestXrayCompatibilityDownloadAliases(t *testing.T) {
	input := json.RawMessage(`{"path":"/test","mode":"packet-up","unknown":{"value":1},"extra":{"xmux":{"maxConcurrency":16},"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"example.com","alpn":["h3"]},"xhttpSettings":{"path":"/test","extra":{"sessionPlacement":"header","sessionKey":"X-Download"}}}}}`)
	data, err := normalizeXHTTPSettings(input)
	if err != nil {
		t.Fatal(err)
	}
	var preserved map[string]json.RawMessage
	json.Unmarshal(data, &preserved)
	if string(preserved["unknown"]) != `{"value":1}` {
		t.Fatal("unknown settings lost")
	}
	var config coreConf.SplitHTTPConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	transport := built.(*splithttp.Config)
	if transport.Xmux.MaxConcurrency.From != 16 || transport.DownloadSettings.Address.AsAddress().String() != "127.0.0.1" {
		t.Fatal("download entry or XMUX lost")
	}
	nested, err := transport.DownloadSettings.TransportSettings[0].Settings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	download := nested.(*splithttp.Config)
	if download.SessionIDPlacement != "header" || download.SessionIDKey != "X-Download" {
		t.Fatalf("download aliases lost: %+v", download)
	}
}

func TestXrayCompatibilityInvalidSettings(t *testing.T) {
	for _, input := range []string{`{`, `[]`, `{"extra":[]}`, `{"downloadSettings":[]}`, `{"downloadSettings":{"xhttpSettings":[]}}`} {
		if _, err := normalizeXHTTPSettings(json.RawMessage(input)); err == nil {
			t.Fatalf("accepted invalid settings: %s", input)
		}
	}
}

func TestXrayCompatibilityRemovedCiphers(t *testing.T) {
	options := xhttpOptions(t, t.TempDir())
	options.XrayOptions.ALPN = nil
	for _, cipher := range []string{"none", "plain", "NONE"} {
		node := &panel.NodeInfo{Type: "shadowsocks", Common: &panel.CommonNode{ServerPort: 12345}, Shadowsocks: &panel.ShadowsocksNode{Cipher: cipher}}
		if _, err := buildInbound(options, node, "test"); err == nil {
			t.Fatalf("accepted removed cipher %s", cipher)
		}
	}
}
