package sing

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/externalweb"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	anytls "github.com/sagernet/sing-anytls"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
)

// Exercise both protocols through actual OpenSSL/nginx processes, including
// a second node added while the first is live and all supported ALPN cases.
func TestExternalVMessAndAnyTLSFrontends(t *testing.T) {
	if !externalweb.SupportsAllTLSProxies() {
		t.Skip("external-web-v2 protocol core not included")
	}
	for _, binary := range []string{"nginx", "haproxy", "python3"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skip("optional frontend test requires " + binary)
		}
	}
	root, err := os.MkdirTemp("", "v2bx-protocol-web-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	os.Chmod(root, 0755)
	os.WriteFile(root+"/index.html", []byte("external protocol website"), 0644)
	certFile, keyFile := writeTestCertificate(t)
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
	s.frontends.HTTPListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(freeTCPPort(t)))
	s.frontends.StatusFile = root + "/ready.json"
	user := panel.UserInfo{Id: 9, Uuid: "c0ffee00-0000-4000-8000-000000000009"}
	echo := startEchoServer(t)
	addresses := map[string]string{}
	for _, protocol := range []string{"vmess", "anytls"} {
		port := freeTCPPort(t)
		tag := "external-" + protocol
		var config conf.Options
		if err = json.Unmarshal([]byte(fmt.Sprintf(`{"Core":"sing","ListenIP":"127.0.0.1","CertConfig":{"CertMode":"file","CertDomain":"localhost","CertFile":%q,"KeyFile":%q,"RejectUnknownSni":true},"FallBackSite":{"Enable":true,"Root":%q},"ExternalWeb":{"Enable":true},"VMessConfig":{"RequireEncryption":true,"HandshakeTimeout":3,"TrafficShaping":{"Enable":true}},"AnyTLSConfig":{"HandshakeTimeout":3,"TrafficShaping":{"Enable":true}}}`, certFile, keyFile, root)), &config); err != nil {
			t.Fatal(err)
		}
		info := &panel.NodeInfo{Type: protocol, Security: panel.Tls, Common: &panel.CommonNode{ServerPort: port}}
		if protocol == "vmess" {
			info.VAllss = &panel.VAllssNode{Network: "tcp"}
			info.Common = &info.VAllss.CommonNode
			info.Common.ServerPort = port
		} else {
			info.AnyTls = &panel.AnyTlsNode{}
		}
		if err = s.AddNode(tag, info, &config); err != nil {
			t.Fatal(err)
		}
		limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
		defer limiter.DeleteLimiter(tag)
		if _, err = s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
			t.Fatal(err)
		}
		addresses[protocol] = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	for _, protocol := range []string{"vmess", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			addr := addresses[protocol]
			for _, h2 := range []bool{false, true} {
				transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}, ForceAttemptHTTP2: h2}
				client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
				for _, path := range []string{"/", "/missing"} {
					response, err := client.Get("https://" + addr + path)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if h2 && response.ProtoMajor != 2 {
						t.Fatal("HTTP/2 ALPN was lost")
					}
					if !strings.HasPrefix(response.Header.Get("Server"), "nginx") {
						t.Fatal("request did not reach nginx")
					}
					if path == "/" && (response.StatusCode != 200 || string(body) != "external protocol website") {
						t.Fatalf("website: %d %q", response.StatusCode, body)
					}
					if path == "/missing" && response.StatusCode != 404 {
						t.Fatal(response.Status)
					}
				}
				transport.CloseIdleConnections()
			}
			for _, alpn := range [][]string{nil, {"http/1.1"}, {"h2"}} {
				tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: alpn}
				if protocol == "vmess" {
					for _, security := range []string{"auto", "none"} {
						raw, err := tls.Dial("tcp", addr, tlsConfig)
						if err != nil {
							t.Fatal(err)
						}
						client, err := vmess.NewClient(user.Uuid, security, 0)
						if err != nil {
							raw.Close()
							t.Fatal(err)
						}
						conn := client.DialEarlyConn(raw, M.ParseSocksaddr(echo))
						checkExternalEcho(t, conn)
						conn.Close()
					}
				} else {
					client, err := anytls.NewClient(anytls.ClientOptions{Password: user.Uuid, DialOut: func(ctx context.Context) (net.Conn, error) {
						return (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", addr)
					}})
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
					conn, err := client.DialContext(ctx, M.ParseSocksaddr(echo))
					if err != nil {
						cancel()
						client.Close()
						t.Fatal(err)
					}
					checkExternalEcho(t, conn)
					conn.Close()
					cancel()
					client.Close()
				}
			}
			if up, down := s.GetUserTraffic("external-"+protocol, user.Uuid, false); up == 0 || down == 0 {
				t.Fatalf("lost user accounting: %d/%d", up, down)
			}
		})
	}
	if err = s.DelNode("external-vmess"); err != nil {
		t.Fatal(err)
	}
	// Removing one node must not stop the other's TLS or web listeners.
	conn, err := tls.Dial("tcp", addresses["anytls"], &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err = s.DelNode("external-anytls"); err != nil {
		t.Fatal(err)
	}
}

func checkExternalEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
		t.Fatalf("proxy reply %q: %v", reply, err)
	}
}

func TestExternalWebProtocolRestrictions(t *testing.T) {
	var config conf.Options
	if err := json.Unmarshal([]byte(`{"Core":"sing","CertConfig":{"CertMode":"file","CertFile":"cert.pem","KeyFile":"key.pem"},"ExternalWeb":{"Enable":true}}`), &config); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		info  panel.NodeInfo
		valid bool
	}{
		{"VMess TCP+TLS", panel.NodeInfo{Type: "vmess", Security: panel.Tls, VAllss: &panel.VAllssNode{Network: "tcp"}}, true},
		{"VMess without TLS", panel.NodeInfo{Type: "vmess", Security: panel.None, VAllss: &panel.VAllssNode{Network: "tcp"}}, false},
		{"VMess WebSocket", panel.NodeInfo{Type: "vmess", Security: panel.Tls, VAllss: &panel.VAllssNode{Network: "ws"}}, false},
		{"VMess HTTP header", panel.NodeInfo{Type: "vmess", Security: panel.Tls, VAllss: &panel.VAllssNode{Network: "tcp", NetworkSettings: json.RawMessage(`{"header":{"type":"http"}}`)}}, false},
		{"native AnyTLS", panel.NodeInfo{Type: "anytls", Security: panel.Tls, AnyTls: &panel.AnyTlsNode{}}, true},
		{"AnyTLS without TLS", panel.NodeInfo{Type: "anytls", Security: panel.None, AnyTls: &panel.AnyTlsNode{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.info.Common = &panel.CommonNode{ServerPort: 443}
			if err := validateExternalWeb(&tc.info, &config); (err == nil) != tc.valid {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}
