package xray

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func xhttpOptions(t *testing.T, dir string) *conf.Options {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for name, data := range map[string][]byte{certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), keyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})} {
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var options conf.Options
	data, _ := json.Marshal(map[string]any{"Core": "xray", "ListenIP": "127.0.0.1", "ALPN": []string{"h3"}, "DisableSniffing": true, "CertConfig": map[string]any{"CertMode": "file", "CertFile": certFile, "KeyFile": keyFile}})
	if err := json.Unmarshal(data, &options); err != nil {
		t.Fatal(err)
	}
	return &options
}

func xhttpNode(port int) *panel.NodeInfo {
	return &panel.NodeInfo{Type: "vless", Security: panel.Tls, Common: &panel.CommonNode{ServerPort: port}, VAllss: &panel.VAllssNode{Network: "xhttp", NetworkSettings: json.RawMessage(`{"path":"/test","mode":"auto"}`)}}
}

func TestXHTTPValidation(t *testing.T) {
	base := xhttpOptions(t, t.TempDir())
	cases := []struct {
		name   string
		change func(*conf.Options, *panel.NodeInfo)
		want   string
	}{
		{"mixed-alpn", func(o *conf.Options, n *panel.NodeInfo) { o.XrayOptions.ALPN = []string{"h3", "h2"} }, "only h3"},
		{"tcp", func(o *conf.Options, n *panel.NodeInfo) { n.VAllss.Network = "tcp" }, "xhttp transport"},
		{"no-tls", func(o *conf.Options, n *panel.NodeInfo) { n.Security = panel.None }, "requires TLS"},
		{"no-certificate", func(o *conf.Options, n *panel.NodeInfo) { o.CertConfig.CertMode = "none" }, "certificate"},
		{"proxy-protocol", func(o *conf.Options, n *panel.NodeInfo) { o.XrayOptions.EnableProxyProtocol = true }, "PROXY protocol"},
		{"vision", func(o *conf.Options, n *panel.NodeInfo) { n.VAllss.Flow = "xtls-rprx-vision" }, "empty VLESS flow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := *base
			opts := *base.XrayOptions
			cert := *base.CertConfig
			o.XrayOptions = &opts
			o.CertConfig = &cert
			n := xhttpNode(443)
			tc.change(&o, n)
			_, err := buildInbound(&o, n, "test")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
	for _, network := range []string{"xhttp", "splithttp"} {
		n := xhttpNode(443)
		n.VAllss.Network = network
		n.VAllss.NetworkSettings = nil
		if _, err := buildInbound(base, n, "test"); err != nil {
			t.Fatalf("%s with default settings: %v", network, err)
		}
	}
}

// Each forwarder supplies a separate public UDP entry to the SAME H3 inbound.
func xhttpUDPEntry(t *testing.T, server int) (int, *atomic.Int64) {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: server})
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close(); back.Close() })
	count := new(atomic.Int64)
	go func() {
		buf := make([]byte, 65536)
		n, client, err := front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		count.Add(1)
		if _, err = back.Write(buf[:n]); err != nil {
			return
		}
		go func() {
			b := make([]byte, 65536)
			for {
				n, err := back.Read(b)
				if err != nil {
					return
				}
				if _, err = front.WriteToUDP(b[:n], client); err != nil {
					return
				}
			}
		}()
		for {
			n, _, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			count.Add(1)
			if _, err = back.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	return front.LocalAddr().(*net.UDPAddr).Port, count
}

func xhttpClient(t *testing.T, upload, download int, mode, id, certFile, alpn string) *core.Instance {
	t.Helper()
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("invalid test certificate")
	}
	hash := sha256.Sum256(block.Bytes)
	tlsSettings := map[string]any{"serverName": "localhost", "pinnedPeerCertSha256": hex.EncodeToString(hash[:]), "alpn": []string{alpn}}
	transport := map[string]any{"path": "/test", "mode": mode}
	if download != 0 {
		transport["extra"] = map[string]any{"downloadSettings": map[string]any{"address": "127.0.0.1", "port": download, "network": "xhttp", "security": "tls", "tlsSettings": tlsSettings, "xhttpSettings": map[string]any{"path": "/test"}}}
	}
	data, err := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": upload, "users": []any{map[string]any{"id": id, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "xhttp", "security": "tls", "tlsSettings": tlsSettings, "xhttpSettings": transport}}}})
	if err != nil {
		t.Fatal(err)
	}
	var c coreConf.Config
	if err = json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	built, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	client, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Start(); err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestXHTTPH3RoundTrip(t *testing.T) { xhttpRoundTrip(t, "h3") }
func TestXHTTPH2RoundTrip(t *testing.T) { xhttpRoundTrip(t, "h2") }

func xhttpRoundTrip(t *testing.T, alpn string) {
	options := xhttpOptions(t, t.TempDir())
	options.XrayOptions.ALPN = []string{alpn}
	port := 0
	if alpn == "h2" {
		socket, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = socket.Addr().(*net.TCPAddr).Port
		socket.Close()
	} else {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = socket.LocalAddr().(*net.UDPAddr).Port
		socket.Close()
	}
	n := xhttpNode(port)
	instance, err := New(&conf.CoreConfig{XrayConfig: conf.NewXrayConfig()})
	if err != nil {
		t.Fatal(err)
	}
	server := instance.(*Xray)
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	const tag = "xhttp-h3-test"
	const id = "c76d3274-fc67-4691-b3f3-4088491c23ee"
	users := []panel.UserInfo{{Id: 1, Uuid: id}}
	limiter.Init()
	limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	if err = server.AddNode(tag, n, options); err != nil {
		t.Fatal(err)
	}
	if _, err = server.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: n}); err != nil {
		t.Fatal(err)
	}
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	target := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port))
	payload := bytes.Repeat([]byte("xhttp-h3-echo"), 4096)
	for _, tc := range []struct {
		mode  string
		split bool
	}{{"packet-up", false}, {"stream-up", false}, {"stream-one", false}, {"packet-up", true}, {"stream-up", true}} {
		if tc.split && alpn != "h3" {
			continue
		}
		t.Run(fmt.Sprintf("%s/split=%v", tc.mode, tc.split), func(t *testing.T) {
			upload, download := port, 0
			var upCount, downCount *atomic.Int64
			if tc.split {
				upload, upCount = xhttpUDPEntry(t, port)
				download, downCount = xhttpUDPEntry(t, port)
			}
			client := xhttpClient(t, upload, download, tc.mode, id, options.CertConfig.CertFile, alpn)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := core.Dial(ctx, client, target)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err = c.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(c, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("corrupted echo")
			}
			if tc.split && (upCount.Load() == 0 || downCount.Load() == 0) {
				t.Fatal("both UDP entries must carry traffic")
			}
		})
	}
	roundTrips := 5
	if alpn == "h2" {
		roundTrips = 3
	}
	traffic, err := server.GetUserTrafficSlice(tag, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(traffic) != 1 || traffic[0].UID != 1 || traffic[0].Upload < int64(len(payload)*roundTrips) || traffic[0].Download < int64(len(payload)*roundTrips) {
		t.Fatalf("missing user traffic: %+v", traffic)
	}
	if err = server.DelUsers(users, tag, n); err != nil {
		t.Fatal(err)
	}
	t.Run("removed-user", func(t *testing.T) {
		client := xhttpClient(t, port, 0, "packet-up", id, options.CertConfig.CertFile, alpn)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := core.Dial(ctx, client, target)
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = c.Write(payload[:32]); err != nil {
			return
		}
		b := make([]byte, 1)
		if n, err := c.Read(b); n != 0 || err == nil {
			t.Fatal("removed user could still proxy data")
		}
	})
}
