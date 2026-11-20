package node

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/InazumaV/V2bX/limiter"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
)

func TestAuditRuleHotReloadKeepsRunningNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			io.WriteString(w, `{"server_port":443,"base_config":{"pull_interval":60,"push_interval":60},"routes":[{"id":1,"action":"block","match":["["]}]}`)
		case "/api/v1/server/UniProxy/user":
			io.WriteString(w, `{"users":[]}`)
		case "/api/v1/server/UniProxy/alivelist":
			io.WriteString(w, `{"alive":{}}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	api, err := panel.New(&conf.ApiConfig{APIHost: srv.URL, Key: "test", NodeType: "anytls", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	old := &panel.NodeInfo{Id: 1, Type: "anytls"}
	c := &Controller{apiClient: api, info: old, tag: "test"}
	// No core is installed here: attempting DelNode before validation would panic.
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatal(err)
	}
	if c.info != old {
		t.Fatal("invalid audit rules replaced the running node's configuration")
	}
}

func TestAuditRetryAndInPlaceReload(t *testing.T) {
	var version, fail atomic.Int32
	version.Store(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			v := version.Load()
			etag := fmt.Sprintf("\"v%d\"", v)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", etag)
			fmt.Fprintf(w, `{"server_port":443,"base_config":{"pull_interval":60,"push_interval":60},"routes":[{"id":1,"action":"block","match":["v%d.test"]}]}`, v)
		case "/api/v1/server/UniProxy/user":
			if fail.Load() != 0 {
				w.WriteHeader(503)
				return
			}
			io.WriteString(w, `{"users":[]}`)
		case "/api/v1/server/UniProxy/alivelist":
			io.WriteString(w, `{"alive":{}}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	api, err := panel.New(&conf.ApiConfig{APIHost: srv.URL, Key: "test", NodeType: "anytls", NodeID: 1})
	if err != nil {
		t.Fatal(err)
	}
	old, err := api.GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	api.ConfirmNode(old)
	l := &limiter.Limiter{}
	if err = l.UpdateRule(&old.Rules); err != nil {
		t.Fatal(err)
	}
	c := &Controller{apiClient: api, info: old, tag: "test", limiter: l}
	version.Store(2)
	fail.Store(1)
	c.nodeInfoMonitor()
	if !l.CheckDomainRule("v1.test") {
		t.Fatal("failed poll lost old policy")
	}
	fail.Store(0)
	c.nodeInfoMonitor() // nil core proves DelNode was never called
	if l.CheckDomainRule("v1.test") || !l.CheckDomainRule("v2.test") {
		t.Fatal("failed to retry changed rules")
	}
	if n, e := api.GetNodeInfo(); e != nil || n != nil {
		t.Fatal("applied version was not confirmed")
	}
}
func TestAuditVisitDelivery(t *testing.T) {
	var allow atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/visitRule":
			if r.Header.Get("If-None-Match") == "v1" {
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", "v1")
			io.WriteString(w, `{"suffixes":["example.org"],"keywords":["track"],"regexes":["^news"]}`)
		case "/api/v1/server/UniProxy/visit":
			if !allow.Load() {
				w.WriteHeader(503)
				return
			}
			var visits []panel.Visit
			if e := json.NewDecoder(r.Body).Decode(&visits); e != nil || len(visits) != 5 {
				t.Errorf("visits %+v %v", visits, e)
				return
			}
			for i, hit := range []string{"blocked.test", "example.org", "kw:track", "re:^news", "protocol:bittorrent"} {
				v := visits[i]
				if i == 0 && (v.Destination != "sub.blocked.test" || v.Time <= 0 || v.BlockRouteID != 41) {
					t.Errorf("invalid blacklist event: %+v", v)
				}
				if v.UID != 7 || v.Source != "127.0.0.1" || v.Hit != hit || (v.Status == "rejected") != (i == 0 || i == 4) {
					t.Errorf("visit %+v", v)
				}
			}
			io.WriteString(w, `{"data":true}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	api, _ := panel.New(&conf.ApiConfig{APIHost: srv.URL, NodeType: "tuic", Key: "test", NodeID: 1})
	c := Controller{apiClient: api, tag: "test"}
	ctx := context.Background()
	limiter.Init()
	l := limiter.AddLimiter("test", &conf.LimitConfig{}, []panel.UserInfo{{Id: 7, Uuid: "user"}}, nil)
	defer limiter.DeleteLimiter("test")
	l.SetVisits(&c.visits)
	// A policy rejection must survive a cold start with no observation list.
	l.RecordVisit("test", "user", "127.0.0.1", "sub.blocked.test:443", "", limiter.RuleHit{Label: "blocked.test", RouteID: 41})
	l.RecordVisit("test", "user", "127.0.0.1", "unwatched.test:443", "", limiter.RuleHit{})
	c.refreshVisits(ctx)
	c.refreshVisits(ctx)
	for _, d := range []string{"private.test", "sub.example.org", "tracker.test", "news.test"} {
		l.RecordVisit("test", "user", "127.0.0.1", d, "", limiter.RuleHit{})
	}
	l.RecordVisit("test", "user", "127.0.0.1", "192.0.2.1:80", "", limiter.RuleHit{Label: "protocol:bittorrent"})
	c.flushVisits(ctx)
	if len(c.visits.Batch()) != 5 {
		t.Fatal("lost failed batch")
	}
	allow.Store(true)
	c.flushVisits(ctx)
	if len(c.visits.Batch()) != 0 {
		t.Fatal("acknowledged batch retained")
	}
}
