package sing

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// captureConn records a client's first flight, to send it as a raw probe.
type captureConn struct {
	net.Conn
	data bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) { return c.data.Write(p) }

type fragmentedFirstWriteConn struct {
	net.Conn
	started bool
}

func (c *fragmentedFirstWriteConn) Write(p []byte) (int, error) {
	if c.started || len(p) <= 7 {
		return c.Conn.Write(p)
	}
	c.started = true
	n, err := c.Conn.Write(p[:7])
	if err != nil {
		return n, err
	}
	// Force a separate first read/TLS record, rather than relying on local
	// TCP segmentation. The remainder is still the same valid VMess stream.
	time.Sleep(10 * time.Millisecond)
	m, err := c.Conn.Write(p[7:])
	return n + m, err
}

// VMess nodes without transport answer probes with the built-in site, over
// plain TCP as well as TLS, and keep serving real clients.
func TestVMessFallbackSiteAndHardening(t *testing.T) {
	user := panel.UserInfo{Id: 7, Uuid: "c0ffee00-0000-4000-8000-000000000007"}
	certFile, keyFile := writeTestCertificate(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "index.html"), []byte("vmess site"), 0o644)
	echoAddr := startEchoServer(t)

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

	addNode := func(tag string, security int, transports ...string) string {
		port := freeTCPPort(t)
		info := &panel.NodeInfo{Type: "vmess", Security: security, VAllss: &panel.VAllssNode{Network: "tcp"}}
		if len(transports) > 0 {
			info.VAllss.Network = transports[0]
			info.VAllss.NetworkSettings = json.RawMessage(`{"path":"/compat","serviceName":"compat"}`)
		}
		info.Common = &info.VAllss.CommonNode
		info.Common.ServerPort = port
		var options conf.Options
		err := json.Unmarshal([]byte(fmt.Sprintf(`{"Core": "sing", "ListenIP": "127.0.0.1",
			"CertConfig": {"CertMode": "file", "CertFile": %q, "KeyFile": %q},
			"FallBackSite": {"Enable": true, "Root": %q, "RedirectHTTP": true},
			"VMessConfig": {"RequireEncryption": true, "HandshakeTimeout": 1, "TrafficShaping": {"Enable": true}}}`, certFile, keyFile, root)), &options)
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
	plainAddr := addNode("vmess-plain-test", panel.None)
	tlsAddr := addNode("vmess-tls-test", panel.Tls)

	dialPlain := func(t *testing.T, addr string) net.Conn {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		return conn
	}
	dialTLS := func(t *testing.T, addr string, nextProtos ...string) net.Conn {
		conn := tls.Client(dialPlain(t, addr), &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: nextProtos})
		if err := conn.Handshake(); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	echo := func(t *testing.T, conn net.Conn, security string) {
		client, err := vmess.NewClient(user.Uuid, security, 0)
		if err != nil {
			t.Fatal(err)
		}
		vmessConn := client.DialEarlyConn(conn, M.ParseSocksaddr(echoAddr))
		payload := bytes.Repeat([]byte("ping"), 5000)
		go vmessConn.Write(payload)
		reply := make([]byte, len(payload))
		if _, err = io.ReadFull(vmessConn, reply); err != nil || !bytes.Equal(reply, payload) {
			t.Fatalf("%s echo failed: %v", security, err)
		}
	}
	readHTTP := func(t *testing.T, conn net.Conn) (int, string) {
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("no HTTP response: %v", err)
		}
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}

	t.Run("plain HTTP probe gets the site", func(t *testing.T) {
		conn := dialPlain(t, plainAddr)
		io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		if status, body := readHTTP(t, conn); status != http.StatusOK || body != "vmess site" {
			t.Fatalf("got %d %q", status, body)
		}
	})
	t.Run("plain short garbage with EOF is answered at once", func(t *testing.T) {
		conn := dialPlain(t, plainAddr)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		io.WriteString(conn, "hello\r\n")
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if status, _ := readHTTP(t, conn); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	})
	t.Run("plain partial AuthID waits only for the handshake budget", func(t *testing.T) {
		conn := dialPlain(t, plainAddr)
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		start := time.Now()
		io.WriteString(conn, "hello\r\n")
		if status, _ := readHTTP(t, conn); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
		if elapsed := time.Since(start); elapsed < 800*time.Millisecond || elapsed > 2500*time.Millisecond {
			t.Fatalf("partial request answered after %v", elapsed)
		}
	})
	t.Run("plain binary line gets 400", func(t *testing.T) {
		// Like any web server, the site waits for the end of the request line.
		conn := dialPlain(t, plainAddr)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write(append(bytes.Repeat([]byte{0x9c, 0x31, 0xe7}, 100), '\r', '\n'))
		if status, _ := readHTTP(t, conn); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	})
	t.Run("plain client proxies", func(t *testing.T) {
		echo(t, dialPlain(t, plainAddr), "auto")
	})
	t.Run("plain fragmented client proxies", func(t *testing.T) {
		echo(t, &fragmentedFirstWriteConn{Conn: dialPlain(t, plainAddr)}, "auto")
	})
	t.Run("plain unencrypted client goes to the site", func(t *testing.T) {
		client, _ := vmess.NewClient(user.Uuid, "none", 0)
		capture := &captureConn{}
		client.DialEarlyConn(capture, M.ParseSocksaddr(echoAddr)).Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		conn := dialPlain(t, plainAddr)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write(capture.data.Bytes())
		if status, _ := readHTTP(t, conn); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	})
	t.Run("TLS h2 probe gets the site", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialTLS(t, tlsAddr, "h2", "http/1.1"), nil
			},
		}}
		defer client.CloseIdleConnections()
		response, err := client.Get("https://localhost/")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.ProtoMajor != 2 || string(body) != "vmess site" {
			t.Fatalf("got %s %q", response.Proto, body)
		}
	})
	t.Run("TLS client proxies, none allowed under TLS", func(t *testing.T) {
		echo(t, dialTLS(t, tlsAddr), "aes-128-gcm")
		echo(t, dialTLS(t, tlsAddr), "none")
	})
	t.Run("TLS fragmented client proxies", func(t *testing.T) {
		echo(t, &fragmentedFirstWriteConn{Conn: dialTLS(t, tlsAddr)}, "aes-128-gcm")
		echo(t, &fragmentedFirstWriteConn{Conn: dialTLS(t, tlsAddr)}, "none")
	})
	for _, network := range []string{"ws", "grpc", "httpupgrade"} {
		t.Run(network+" fragmented client proxies", func(t *testing.T) {
			addr := addNode("vmess-transport-"+network, panel.None, network)
			options := option.V2RayTransportOptions{
				Type:               network,
				WebsocketOptions:   option.V2RayWebsocketOptions{Path: "/compat"},
				GRPCOptions:        option.V2RayGRPCOptions{ServiceName: "compat"},
				HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{Path: "/compat"},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			transport, err := v2ray.NewClientTransport(ctx, &N.DefaultDialer{}, M.ParseSocksaddr(addr), options, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			conn, err := transport.DialContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			echo(t, &fragmentedFirstWriteConn{Conn: conn}, "auto")
		})
	}
}

func TestFallbackSiteApplies(t *testing.T) {
	header := json.RawMessage(`{"header": {"type": "http"}}`)
	for _, test := range []struct {
		info *panel.NodeInfo
		want bool
	}{
		{&panel.NodeInfo{Type: "trojan", Security: panel.Tls}, true},
		{&panel.NodeInfo{Type: "trojan", Security: panel.None}, false},
		{&panel.NodeInfo{Type: "vmess", Security: panel.None, VAllss: &panel.VAllssNode{Network: "tcp"}}, true},
		{&panel.NodeInfo{Type: "vmess", Security: panel.Tls, VAllss: &panel.VAllssNode{Network: "tcp"}}, true},
		{&panel.NodeInfo{Type: "vmess", Security: panel.Tls, VAllss: &panel.VAllssNode{Network: "ws"}}, false},
		{&panel.NodeInfo{Type: "vmess", Security: panel.None, VAllss: &panel.VAllssNode{Network: "tcp", NetworkSettings: header}}, false},
		{&panel.NodeInfo{Type: "vless", Security: panel.Tls, VAllss: &panel.VAllssNode{Network: "tcp"}}, false},
	} {
		if got := fallbackSiteApplies(test.info); got != test.want {
			t.Errorf("%s security %d %+v: got %v", test.info.Type, test.info.Security, test.info.VAllss, got)
		}
	}
}
