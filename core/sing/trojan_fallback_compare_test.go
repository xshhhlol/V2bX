package sing

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Compare the same site over real TLS sockets, directly and through the full
// V2bX Trojan inbound, including routing and the fallback relay.
func TestTrojanFallbackComparison(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	direct := httptest.NewUnstartedServer(siteHandler(siteFS("")))
	direct.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	direct.EnableHTTP2 = true
	direct.Config.ReadHeaderTimeout = 30 * time.Second
	direct.Config.IdleTimeout = 2 * time.Minute
	direct.StartTLS()
	defer direct.Close()
	const tag = "trojan-comparison"
	user := panel.UserInfo{Id: 1, Uuid: "comparison-password"}
	limiter.Init()
	c, err := New(&conf.CoreConfig{Type: "sing", SingConfig: conf.NewSingConfig()})
	if err != nil {
		t.Fatal(err)
	}
	s := c.(*Sing)
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	port := freeTCPPort(t)
	var options conf.Options
	err = json.Unmarshal([]byte(fmt.Sprintf(`{"Core":"sing","ListenIP":"127.0.0.1","CertConfig":{"CertMode":"file","CertFile":%q,"KeyFile":%q},"FallBackSite":{"Enable":true}}`, certFile, keyFile)), &options)
	if err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{Type: "trojan", Security: panel.Tls, Trojan: &panel.TrojanNode{Network: "tcp"}}
	info.Trojan.CommonNode.ServerPort = port
	info.Common = &info.Trojan.CommonNode
	if err = s.AddNode(tag, info, &options); err != nil {
		t.Fatal(err)
	}
	defer s.DelNode(tag)
	limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	defer limiter.DeleteLimiter(tag)
	if _, err = s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	dial := func(addr string) *tls.Conn {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		return conn
	}
	type result struct {
		code                     int
		body, allow, contentType string
	}
	for _, tc := range []struct {
		name      string
		chunks    []string
		halfClose bool
	}{
		{"fragmented GET", []string{"G", "ET / HTTP/1.1\r\n", "Host: localhost\r\nConnection: close\r\n\r\n"}, false},
		{"HEAD", []string{"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"}, false},
		{"missing", []string{"GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"}, false},
		{"method", []string{"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"}, false},
		{"malformed", []string{"hello\r\n"}, false},
		{"complete half close", []string{"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"}, true},
		{"incomplete half close", []string{"GET / HTTP/1.1\r\nHost:"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var outcomes []result
			for _, addr := range []string{direct.Listener.Addr().String(), proxy} {
				conn := dial(addr)
				defer conn.Close()
				for _, chunk := range tc.chunks {
					if _, err = io.WriteString(conn, chunk); err != nil {
						t.Fatal(err)
					}
				}
				if tc.halfClose {
					if err = conn.CloseWrite(); err != nil {
						t.Fatal(err)
					}
				}
				method := "GET"
				if tc.name == "HEAD" {
					method = "HEAD"
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
				if err != nil {
					t.Fatalf("%s: %v", addr, err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				outcomes = append(outcomes, result{response.StatusCode, string(body), response.Header.Get("Allow"), response.Header.Get("Content-Type")})
			}
			if outcomes[0] != outcomes[1] {
				t.Fatalf("direct %#v; fallback %#v", outcomes[0], outcomes[1])
			}
		})
	}
	t.Run("header timeout budget", func(t *testing.T) {
		type timedResult struct {
			name    string
			code    int
			elapsed time.Duration
			err     error
		}
		results := make(chan timedResult, 4)
		for _, payload := range []string{"", "0123456789abcdef"} {
			for _, addr := range []string{direct.Listener.Addr().String(), proxy} {
				conn := dial(addr)
				conn.SetDeadline(time.Now().Add(34 * time.Second))
				defer conn.Close()
				go func() {
					start := time.Now()
					if payload != "" {
						if _, err := io.WriteString(conn, payload); err != nil {
							results <- timedResult{err: err}
							return
						}
					}
					response, err := http.ReadResponse(bufio.NewReader(conn), nil)
					result := timedResult{name: payload, elapsed: time.Since(start), err: err}
					if response != nil {
						result.code = response.StatusCode
						response.Body.Close()
					}
					results <- result
				}()
			}
		}
		for range 4 {
			result := <-results
			valid := result.code == http.StatusBadRequest && result.err == nil
			if result.name == "" {
				valid = result.code == 0 && (result.err == io.EOF || result.err == io.ErrUnexpectedEOF)
			}
			if !valid || result.elapsed < 28*time.Second || result.elapsed > 33*time.Second {
				t.Errorf("header deadline (%q): status=%d elapsed=%s err=%v", result.name, result.code, result.elapsed, result.err)
			}
		}
	})

	t.Run("HTTP2", func(t *testing.T) {
		var bodies []string
		for _, addr := range []string{direct.Listener.Addr().String(), proxy} {
			transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}, ForceAttemptHTTP2: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
			response, err := client.Get("https://" + addr + "/about/")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.ProtoMajor != 2 || response.StatusCode != 200 {
				t.Fatalf("%s: %v", response.Status, err)
			}
			bodies = append(bodies, string(body))
		}
		if bodies[0] != bodies[1] {
			t.Fatal("HTTP/2 body differs")
		}
	})
	t.Run("standard client ALPN compatibility", func(t *testing.T) {
		echo := startEchoServer(t)
		for _, alpn := range [][]string{nil, {"http/1.1"}, {"h2", "http/1.1"}} {
			raw, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", proxy, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: alpn})
			if err != nil {
				t.Fatal(err)
			}
			conn := trojan.NewClientConn(raw, trojan.Key(user.Uuid), M.ParseSocksaddr(echo))
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 4)
			if _, err = io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
				t.Fatalf("ALPN %v reply %q: %v", alpn, reply, err)
			}
		}
	})

	t.Run("fragmented authenticated client", func(t *testing.T) {
		echo := startEchoServer(t)
		conn := dial(proxy)
		defer conn.Close()
		request := buf.New()
		defer request.Release()
		key := trojan.Key(user.Uuid)
		request.Write(key[:])
		request.Write(trojan.CRLF)
		request.WriteByte(trojan.CommandTCP)
		if err := M.SocksaddrSerializer.WriteAddrPort(request, M.ParseSocksaddr(echo)); err != nil {
			t.Fatal(err)
		}
		request.Write(trojan.CRLF)
		request.WriteString("ping")
		for _, b := range request.Bytes() {
			if _, err := conn.Write([]byte{b}); err != nil {
				t.Fatal(err)
			}
		}
		reply := make([]byte, 4)
		if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
			t.Fatalf("reply %q: %v", reply, err)
		}
	})
}
