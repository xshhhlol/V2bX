package sing

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
)

// TestAnyTLSFallbackWithLimiter runs an AnyTLS node through the V2bX hook and
// limiter: unauthenticated requests must reach the fallback site, while
// authenticated users are still limited and counted.
func TestAnyTLSFallbackWithLimiter(t *testing.T) {
	const tag = "anytls-fallback-test"
	user := panel.UserInfo{Id: 1, Uuid: "c0ffee00-0000-4000-8000-000000000001"}

	certFile, keyFile := writeTestCertificate(t)
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "fallback-ok")
	}))
	defer fallback.Close()
	fallbackHost, fallbackPort, _ := net.SplitHostPort(fallback.Listener.Addr().String())
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

	nodeConfig := fmt.Sprintf(`{"Core": "sing", "ListenIP": "127.0.0.1",
		"CertConfig": {"CertMode": "file", "CertFile": %q, "KeyFile": %q},
		"FallBackConfigs": {"FallBack": {"Server": %q, "ServerPort": %q}}}`,
		certFile, keyFile, fallbackHost, fallbackPort)
	var options conf.Options
	if err = json.Unmarshal([]byte(nodeConfig), &options); err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{
		Type:     "anytls",
		Security: panel.Tls,
		Common:   &panel.CommonNode{ServerPort: port},
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
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	t.Run("fallback", func(t *testing.T) {
		conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read fallback response: %v", err)
		}
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != "fallback-ok" {
			t.Fatalf("fallback body %q, err %v", body, err)
		}
		if _, ok := s.hookServer.counter.Load(tag); ok {
			if up, down := s.GetUserTraffic(tag, "", false); up+down != 0 {
				t.Fatalf("fallback traffic counted as a user: up %d down %d", up, down)
			}
		}
	})

	t.Run("authenticated", func(t *testing.T) {
		client, err := anytls.NewClient(anytls.ClientOptions{
			Password: user.Uuid,
			DialOut: func(ctx context.Context) (net.Conn, error) {
				var dialer tls.Dialer
				dialer.Config = tlsConfig
				return dialer.DialContext(ctx, "tcp", serverAddr)
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
		if _, err = io.WriteString(conn, "ping"); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 4)
		if _, err = io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
			t.Fatalf("echo reply %q, err %v", reply, err)
		}
		if up, down := s.GetUserTraffic(tag, user.Uuid, false); up == 0 || down == 0 {
			t.Fatalf("user traffic not counted: up %d down %d", up, down)
		}
	})
}

func writeTestCertificate(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "cert.key")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
