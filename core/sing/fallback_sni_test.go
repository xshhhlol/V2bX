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

// TestAnyTLSFallbackALPNAndSNI checks what a prober sees: with a known SNI each
// ALPN reaches a matching web server, with an unknown or missing SNI the TLS
// handshake is refused, and real AnyTLS clients keep working.
func TestAnyTLSFallbackALPNAndSNI(t *testing.T) {
	const tag = "anytls-fallback-sni-test"
	const panelServerName = "node.example.com" // the test certificate only covers localhost
	user := panel.UserInfo{Id: 2, Uuid: "c0ffee00-0000-4000-8000-000000000002"}

	certFile, keyFile := writeTestCertificate(t)
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "site "+r.Proto)
	})
	h1 := httptest.NewServer(site)
	defer h1.Close()
	h2 := httptest.NewUnstartedServer(site)
	h2.Config.Protocols = new(http.Protocols)
	h2.Config.Protocols.SetUnencryptedHTTP2(true)
	h2.Start()
	defer h2.Close()
	echoAddr := startEchoServer(t)
	port := freeTCPPort(t)

	limiter.Init()
	defer limiter.DeleteLimiter(tag)
	c, err := New(&conf.CoreConfig{Type: "sing", SingConfig: conf.NewSingConfig()})
	if err != nil {
		t.Fatal(err)
	}
	s := c.(*Sing)
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	h1Port := h1.Listener.Addr().(*net.TCPAddr).Port
	h2Port := h2.Listener.Addr().(*net.TCPAddr).Port
	nodeConfig := fmt.Sprintf(`{"Core": "sing", "ListenIP": "127.0.0.1",
		"CertConfig": {"CertMode": "file", "CertFile": %q, "KeyFile": %q, "RejectUnknownSni": true},
		"ALPN": ["h2", "http/1.1"],
		"FallBackConfigs": {
			"FallBack": {"Server": "127.0.0.1", "ServerPort": "%d"},
			"FallBackForALPN": {
				"http/1.1": {"Server": "127.0.0.1", "ServerPort": "%d"},
				"h2": {"Server": "127.0.0.1", "ServerPort": "%d"}
			}
		}}`, certFile, keyFile, h1Port, h1Port, h2Port)
	var options conf.Options
	if err = json.Unmarshal([]byte(nodeConfig), &options); err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		Common:   &panel.CommonNode{ServerPort: port, ServerName: panelServerName},
		AnyTls:   &panel.AnyTlsNode{},
	}
	if err = s.AddNode(tag, info, &options); err != nil {
		t.Fatal(err)
	}
	defer s.DelNode(tag)
	limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	if _, err = s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}

	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	dialTLS := func(ctx context.Context, serverName string, nextProtos ...string) (*tls.Conn, error) {
		dialer := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config:    &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: nextProtos},
		}
		conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
		if err != nil {
			return nil, err
		}
		return conn.(*tls.Conn), nil
	}

	t.Run("http/1.1 probe with panel SNI", func(t *testing.T) {
		conn, err := dialTLS(context.Background(), panelServerName, "http/1.1")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+panelServerName+"\r\nConnection: close\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		if string(body) != "site HTTP/1.1" {
			t.Fatalf("got %q", body)
		}
	})

	t.Run("h2 probe with certificate SNI", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialTLS(ctx, "localhost", "h2", "http/1.1")
			},
		}}
		response, err := client.Get("https://localhost/")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if string(body) != "site HTTP/2.0" {
			t.Fatalf("got %q", body)
		}
	})

	t.Run("unknown SNI is refused", func(t *testing.T) {
		for _, serverName := range []string{"", "random.example.org"} {
			conn, err := dialTLS(context.Background(), serverName, "h2", "http/1.1")
			if err == nil {
				conn.Close()
				t.Fatalf("SNI %q completed the handshake", serverName)
			}
			if !strings.Contains(err.Error(), "unrecognized name") {
				t.Fatalf("SNI %q: got %v, want unrecognized name alert", serverName, err)
			}
		}
	})

	t.Run("anytls client", func(t *testing.T) {
		client, err := anytls.NewClient(anytls.ClientOptions{
			Password: user.Uuid,
			DialOut: func(ctx context.Context) (net.Conn, error) {
				return dialTLS(ctx, panelServerName, "h2", "http/1.1")
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
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "ping")
		reply := make([]byte, 4)
		if _, err = io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
			t.Fatalf("echo reply %q, err %v", reply, err)
		}
	})
}
