package sing

import (
	"bufio"
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
	"github.com/InazumaV/V2bX/common/port80"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"
)

func TestExternalTrojanFrontend(t *testing.T) {
	if !externalweb.SupportsTLSProxy() {
		t.Skip("build does not include the optional trusted TLS proxy core")
	}
	for _, binary := range []string{"nginx", "haproxy", "python3"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skip("optional external frontend test requires " + binary)
		}
	}
	certFile, keyFile := writeTestCertificate(t)
	// nginx workers must be able to traverse the public site directory.
	root, err := os.MkdirTemp("", "v2bx-public-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	os.Chmod(root, 0755)
	os.WriteFile(root+"/index.html", []byte("external website"), 0644)
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
	port := freeTCPPort(t)
	info := &panel.NodeInfo{Type: "trojan", Security: panel.Tls, Trojan: &panel.TrojanNode{Network: "tcp"}}
	info.Trojan.CommonNode.ServerPort = port
	info.Common = &info.Trojan.CommonNode
	var config conf.Options
	if err = json.Unmarshal([]byte(fmt.Sprintf(`{"Core":"sing","ListenIP":"127.0.0.1","CertConfig":{"CertMode":"file","CertFile":%q,"KeyFile":%q,"RejectUnknownSni":true},"FallBackSite":{"Enable":true,"Root":%q},"ExternalWeb":{"Enable":true}}`, certFile, keyFile, root)), &config); err != nil {
		t.Fatal(err)
	}
	const tag = "external-test"
	if err = s.AddNode(tag, info, &config); err != nil {
		t.Fatal(err)
	}
	user := panel.UserInfo{Id: 1, Uuid: "external-test-password"}
	limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
	defer limiter.DeleteLimiter(tag)
	if _, err = s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if wrong, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "wrong.example"}); err == nil {
		wrong.Close()
		t.Fatal("unknown SNI accepted")
	}
	malformed, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	malformed.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(malformed, "hello\r\n")
	bad, err := http.ReadResponse(bufio.NewReader(malformed), nil)
	if err != nil {
		t.Fatal(err)
	}
	badBody, _ := io.ReadAll(bad.Body)
	bad.Body.Close()
	malformed.Close()
	if bad.StatusCode != 400 || !strings.HasPrefix(bad.Header.Get("Server"), "nginx") || !strings.Contains(string(badBody), "<html>") {
		t.Fatalf("malformed request bypassed nginx: %d %v %s", bad.StatusCode, bad.Header, badBody)
	}
	for _, h2 := range []bool{false, true} {
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}, ForceAttemptHTTP2: h2}
		client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
		for _, path := range []string{"/", "/missing"} {
			r, err := client.Get("https://" + addr + path)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if h2 && r.ProtoMajor != 2 {
				t.Fatal("HTTP/2 negotiation lost")
			}
			if path == "/" && (r.StatusCode != 200 || string(body) != "external website") {
				t.Fatalf("website: %d %s", r.StatusCode, body)
			}
			if path == "/missing" && (r.StatusCode != 404 || !strings.HasPrefix(r.Header.Get("Server"), "nginx") || strings.Contains(string(body), "404 page not found")) {
				t.Fatalf("unexpected fallback: %d %s %s", r.StatusCode, r.Header, body)
			}
		}
		transport.CloseIdleConnections()
	}
	echo := startEchoServer(t)
	for _, alpn := range [][]string{nil, {"http/1.1"}, {"h2"}} {
		raw, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: alpn})
		if err != nil {
			t.Fatal(err)
		}
		conn := trojan.NewClientConn(raw, trojan.Key(user.Uuid), M.ParseSocksaddr(echo))
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 4)
		if _, err = io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
			t.Fatalf("ALPN %v: %q %v", alpn, reply, err)
		}
		conn.Close()
	}
	// Certificate rotation must reach OpenSSL without restarting V2bX.
	fingerprint := func() string {
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
		if e != nil {
			return ""
		}
		defer conn.Close()
		return string(conn.ConnectionState().PeerCertificates[0].Raw)
	}
	original := fingerprint()
	newCert, newKey := writeTestCertificate(t)
	certBytes, _ := os.ReadFile(newCert)
	keyBytes, _ := os.ReadFile(newKey)
	os.WriteFile(certFile, certBytes, 0600)
	os.WriteFile(keyFile, keyBytes, 0600)
	deadline := time.Now().Add(9 * time.Second)
	rotated := false
	for time.Now().Before(deadline) {
		if current := fingerprint(); current != "" && current != original {
			rotated = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !rotated {
		t.Fatal("OpenSSL did not reload the renewed certificate")
	}
	provider := port80.Provider{}
	if err = provider.Present("localhost", "external-token", "external-key-auth"); err != nil {
		t.Fatal(err)
	}
	defer provider.CleanUp("localhost", "external-token", "external-key-auth")
	request, _ := http.NewRequest("GET", "http://"+s.frontends.HTTPListen+"/.well-known/acme-challenge/external-token", nil)
	request.Host = "localhost"
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(challenge) != "external-key-auth" {
		t.Fatalf("ACME proxy: %d %q %v", response.StatusCode, challenge, err)
	}
	if err = s.DelNode(tag); err != nil {
		t.Fatal(err)
	}
}
