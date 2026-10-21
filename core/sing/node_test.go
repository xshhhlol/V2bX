package sing

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/sagernet/sing-box/option"
)

func anyTLSInboundOptions(t *testing.T, nodeConfig string) *option.AnyTLSInboundOptions {
	t.Helper()
	var c conf.Options
	if err := json.Unmarshal([]byte(nodeConfig), &c); err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		Common:   &panel.CommonNode{ServerPort: 443},
		AnyTls:   &panel.AnyTlsNode{},
	}
	in, err := getInboundOptions("anytls-test", info, &c)
	if err != nil {
		t.Fatal(err)
	}
	return in.Options.(*option.AnyTLSInboundOptions)
}

func TestAnyTLSInboundOptions(t *testing.T) {
	const base = `"Core": "sing", "ListenIP": "0.0.0.0",
		"CertConfig": {"CertMode": "file", "CertFile": "cert.pem", "KeyFile": "cert.key"}`

	options := anyTLSInboundOptions(t, `{`+base+`}`)
	if options.TrafficShaping != nil || options.HandshakeTimeout != 0 || options.Fallback != nil || len(options.FallbackForALPN) != 0 {
		t.Fatalf("default node config changed AnyTLS options: %+v", options)
	}

	options = anyTLSInboundOptions(t, `{`+base+`,
		"FallBackConfigs": {
			"FallBack": {"Server": "127.0.0.1", "ServerPort": "8080"},
			"FallBackForALPN": {"http/1.1": {"Server": "127.0.0.1", "ServerPort": "8081"}}
		},
		"AnyTLSConfig": {"HandshakeTimeout": 5, "TrafficShaping": {"Enable": true, "MaxPaddingBytes": 8192}}
	}`)
	shaping := options.TrafficShaping
	if shaping == nil || !shaping.Enabled || shaping.MaxPaddingBytes != 8192 || shaping.MinRecordSize != 0 || shaping.MaxRecords != 0 {
		t.Fatalf("unexpected traffic shaping %+v", shaping)
	}
	if time.Duration(options.HandshakeTimeout) != 5*time.Second {
		t.Fatalf("handshake timeout %s", time.Duration(options.HandshakeTimeout))
	}
	if options.Fallback == nil || options.Fallback.Server != "127.0.0.1" || options.Fallback.ServerPort != 8080 {
		t.Fatalf("unexpected fallback %+v", options.Fallback)
	}
	if alpn := options.FallbackForALPN["http/1.1"]; alpn == nil || alpn.ServerPort != 8081 {
		t.Fatalf("unexpected ALPN fallback %+v", options.FallbackForALPN)
	}

	// A control node keeps the legacy sender with the section present.
	options = anyTLSInboundOptions(t, `{`+base+`, "AnyTLSConfig": {"TrafficShaping": {"Enable": false, "MaxPaddingBytes": 8192}}}`)
	if options.TrafficShaping != nil {
		t.Fatalf("disabled traffic shaping was passed on: %+v", options.TrafficShaping)
	}
}
