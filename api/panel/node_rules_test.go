package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/InazumaV/V2bX/conf"
)

func TestPanelAuditRules(t *testing.T) {
	for _, nodeType := range []string{"anytls", "tuic", "hysteria2"} {
		t.Run(nodeType, func(t *testing.T) {
			var match any = []string{" example.com ", "regexp:^exact$", "protocol:bittorrent"}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"server_port": 443,
					"base_config": map[string]int{"pull_interval": 60, "push_interval": 60},
					"routes":      []any{map[string]any{"id": 1, "match": match, "action": "block"}},
				})
			}))
			defer srv.Close()
			c, err := New(&conf.ApiConfig{APIHost: srv.URL, Key: "test", NodeType: nodeType, NodeID: 1})
			if err != nil {
				t.Fatal(err)
			}
			n, err := c.GetNodeInfo()
			if err != nil || n.Rules.Regexp[0] != "example.com" || n.Rules.Regexp[1] != "regexp:^exact$" || n.Rules.Protocol[0] != "bittorrent" || n.Rules.RouteIDs["example.com"] != 1 || n.Rules.RouteIDs["protocol:bittorrent"] != 1 {
				t.Fatalf("incorrect audit conversion: %+v, %v", n, err)
			}
			for _, invalid := range []any{map[string]string{"1": "example.com"}, []any{true}, nil, []string{" "}} {
				match = invalid
				if _, err := c.GetNodeInfo(); err == nil {
					t.Fatalf("malformed match %#v was accepted", match)
				}
			}
			match = []string{"new.example"}
			n, err = c.GetNodeInfo()
			if err != nil || n.Rules.Regexp[0] != "new.example" {
				t.Fatalf("rule update not fetched: %+v, %v", n, err)
			}
		})
	}
}
