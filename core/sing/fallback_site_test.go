package sing

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSiteHandler(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "index.html"), []byte("home"), 0o644)
	os.Mkdir(filepath.Join(root, "empty"), 0o755)
	os.Mkdir(filepath.Join(root, ".git"), 0o755)
	os.WriteFile(filepath.Join(root, ".git", "config"), []byte("secret"), 0o644)
	handler := siteHandler(siteFS(root))

	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"GET", "/", 200, "home"},
		{"HEAD", "/", 200, ""},
		{"GET", "/index.html", 301, ""},
		{"GET", "/empty/", 404, ""},
		{"GET", "/.git/config", 404, ""},
		{"GET", "/../index.html", 301, ""},
		{"GET", "/missing", 404, ""},
		{"POST", "/", 405, ""},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
		if recorder.Code != tc.status || tc.body != "" && recorder.Body.String() != tc.body {
			t.Errorf("%s %s: got %d %q, want %d %q", tc.method, tc.path, recorder.Code, recorder.Body.String(), tc.status, tc.body)
		}
	}

	recorder := httptest.NewRecorder()
	siteHandler(siteFS("")).ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "<html") {
		t.Fatalf("built-in page: %d %q", recorder.Code, recorder.Body.String())
	}
}

// TestFallbackSiteBehindPrivateReject uses the route rules the install script
// writes: private destinations are rejected and the default outbound is not
// direct. Probes must still reach the built-in site, while users stay blocked.
func TestFallbackSiteBehindPrivateReject(t *testing.T) {
	const anytlsTag, trojanTag = "anytls-site-test", "trojan-site-test"
	user := panel.UserInfo{Id: 3, Uuid: "c0ffee00-0000-4000-8000-000000000003"}

	certFile, keyFile := writeTestCertificate(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "index.html"), []byte("custom site"), 0o644)
	echoAddr := startEchoServer(t)
	origin := filepath.Join(t.TempDir(), "sing_origin.json")
	os.WriteFile(origin, []byte(`{
		"outbounds": [
			{"tag": "proxy", "type": "socks", "server": "192.0.2.1", "server_port": 1080},
			{"tag": "direct", "type": "direct"}
		],
		"route": {"rules": [{"ip_is_private": true, "action": "reject"}]}
	}`), 0o644)

	limiter.Init()
	singConfig := conf.NewSingConfig()
	singConfig.OriginalPath = origin
	c, err := New(&conf.CoreConfig{Type: "sing", SingConfig: singConfig})
	if err != nil {
		t.Fatal(err)
	}
	s := c.(*Sing)
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	addNode := func(tag string, info *panel.NodeInfo, siteRoot string) string {
		port := freeTCPPort(t)
		info.Common.ServerPort = port
		var options conf.Options
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"Core": "sing", "ListenIP": "127.0.0.1",
			"CertConfig": {"CertMode": "file", "CertFile": %q, "KeyFile": %q},
			"FallBackSite": {"Enable": true, "Root": %q}}`, certFile, keyFile, siteRoot)), &options)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.AddNode(tag, info, &options); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.DelNode(tag) })
		limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
		t.Cleanup(func() { limiter.DeleteLimiter(tag) })
		if _, err = s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	anytlsAddr := addNode(anytlsTag, &panel.NodeInfo{
		Type: "anytls", Security: panel.Tls, Common: &panel.CommonNode{}, AnyTls: &panel.AnyTlsNode{},
	}, root)
	trojanInfo := &panel.NodeInfo{Type: "trojan", Security: panel.Tls, Trojan: &panel.TrojanNode{Network: "tcp"}}
	trojanInfo.Common = &trojanInfo.Trojan.CommonNode
	trojanAddr := addNode(trojanTag, trojanInfo, "")

	dialTLS := func(ctx context.Context, addr string, nextProtos ...string) (*tls.Conn, error) {
		dialer := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config:    &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: nextProtos},
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return conn.(*tls.Conn), nil
	}
	get := func(t *testing.T, addr string, nextProtos ...string) (string, string) {
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialTLS(ctx, addr, nextProtos...)
			},
		}}
		defer client.CloseIdleConnections()
		response, err := client.Get("https://localhost/")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.Proto, string(body)
	}

	t.Run("anytls h2 probe", func(t *testing.T) {
		if proto, body := get(t, anytlsAddr, "h2", "http/1.1"); proto != "HTTP/2.0" || body != "custom site" {
			t.Fatalf("got %s %q", proto, body)
		}
	})
	t.Run("anytls probe without ALPN", func(t *testing.T) {
		conn, err := dialTLS(context.Background(), anytlsAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		if string(body) != "custom site" {
			t.Fatalf("got %q", body)
		}
	})
	t.Run("trojan http/1.1 probe gets built-in page", func(t *testing.T) {
		if proto, body := get(t, trojanAddr, "http/1.1"); proto != "HTTP/1.1" || !strings.Contains(body, "<html") {
			t.Fatalf("got %s %q", proto, body)
		}
	})
	t.Run("users still cannot reach private addresses", func(t *testing.T) {
		client, err := anytls.NewClient(anytls.ClientOptions{
			Password: user.Uuid,
			DialOut: func(ctx context.Context) (net.Conn, error) {
				return dialTLS(ctx, anytlsAddr, "h2", "http/1.1")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx, M.ParseSocksaddr(echoAddr))
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, "ping")
		reply := make([]byte, 4)
		if _, err = io.ReadFull(conn, reply); err == nil {
			t.Fatalf("user reached private echo server: %q", reply)
		}
	})
}
