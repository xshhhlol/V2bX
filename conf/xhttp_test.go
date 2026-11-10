package conf

import (
	"encoding/json"
	"testing"
)

func TestXrayALPNOptions(t *testing.T) {
	for _, data := range []string{
		`{"Core":"xray","ALPN":["h3"],"EnableTFO":true}`,
		`{"Core":"xray","XrayOptions":{"ALPN":["h3"],"EnableTFO":true}}`,
		`{"Core":"xray","ALPN":["h2"],"XrayOptions":{"ALPN":["h3"],"EnableTFO":true}}`,
	} {
		var o Options
		if err := json.Unmarshal([]byte(data), &o); err != nil {
			t.Fatal(err)
		}
		if len(o.XrayOptions.ALPN) != 1 || o.XrayOptions.ALPN[0] != "h3" || !o.XrayOptions.EnableTFO {
			t.Fatalf("options lost: %+v", o.XrayOptions)
		}
	}
}

func TestXrayALPNExample(t *testing.T) {
	c := New()
	if err := c.LoadFromPath("../example/xhttp.json"); err != nil {
		t.Fatal(err)
	}
	if len(c.NodeConfig) != 1 || c.NodeConfig[0].Options.Core != "xray" || len(c.NodeConfig[0].Options.XrayOptions.ALPN) != 1 || c.NodeConfig[0].Options.XrayOptions.ALPN[0] != "h3" {
		t.Fatalf("invalid XHTTP example: %+v", c.NodeConfig)
	}
}
