//go:build with_utls

package sing

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
)

// Construct a real sing REALITY listener with the shared dependency selected by
// Xray. A combined compile alone cannot exercise the private-key API adapter.
func TestXraySharedReality(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core, err := New(&conf.CoreConfig{Type: "sing", SingConfig: conf.NewSingConfig()})
	if err != nil {
		t.Fatal(err)
	}
	server := core.(*Sing)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var options conf.Options
	if err := json.Unmarshal([]byte(`{"Core":"sing","ListenIP":"127.0.0.1"}`), &options); err != nil {
		t.Fatal(err)
	}
	node := &panel.NodeInfo{
		Type: "vless", Security: panel.Reality,
		Common: &panel.CommonNode{ServerPort: freeTCPPort(t)},
		VAllss: &panel.VAllssNode{Network: "tcp", TlsSettings: panel.TlsSettings{
			ServerName: "example.com", ServerPort: "443", ShortId: "0123456789abcdef",
			PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
		}},
	}
	if err := server.AddNode("reality-compat", node, &options); err != nil {
		t.Fatal(err)
	}
	if err := server.DelNode("reality-compat"); err != nil {
		t.Fatal(err)
	}
}
