package hy2

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"go.uber.org/zap"
)

type auditTestUDPWriter struct {
	server.UDPConn
	sent int
}

func (w *auditTestUDPWriter) WriteTo(payload []byte, _ string) (int, error) {
	w.sent++
	return len(payload), nil
}

func TestHy2AuditPacketRuleRefresh(t *testing.T) {
	limiter.Init()
	const tag = "audit-cache-refresh"
	l := limiter.AddLimiter(tag, &conf.LimitConfig{}, nil, nil)
	defer limiter.DeleteLimiter(tag)
	writer := &auditTestUDPWriter{}
	conn := &auditUDPConn{UDPConn: writer, tag: tag}
	const address = "192.0.2.1:443"
	if _, err := conn.WriteTo([]byte("first"), address); err != nil {
		t.Fatal(err)
	}
	if err := l.UpdateRule(&panel.Rules{Regexp: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("blocked"), address); err == nil || writer.sent != 1 {
		t.Fatal("Hy2's cached UDP destination bypassed the updated panel rule")
	}
	if err := l.UpdateRule(&panel.Rules{}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("allowed again"), address); err != nil || writer.sent != 2 {
		t.Fatal("Hy2's cached rejection survived rule removal")
	}
}

func TestHy2PanelAudit(t *testing.T) {
	limiter.Init()
	const tag, user = "audit-hy2", "audit-user"
	l := limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{{Id: 7, Uuid: user}}, nil)
	var visits limiter.VisitMonitor
	if err := visits.Update(&panel.VisitRules{Suffixes: []string{"allowed.example", "127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	l.SetVisits(&visits)
	defer limiter.DeleteLimiter(tag)
	n := &Hysteria2node{Tag: tag, Logger: zap.NewNop()}
	hook, err := n.getRequestHook(&serverConfig{})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := n.getOutboundConfig(&serverConfig{})
	if err != nil {
		t.Fatal(err)
	}
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certs := certServer.TLS.Certificates
	certServer.Close()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.NewServer(&server.Config{
		Conn: conn, TLSConfig: server.TLSConfig{Certificates: certs},
		Authenticator: &V2bX{usersMap: map[string]int{user: 1}},
		Outbound:      outbound, RequestHook: hook, RequestScope: scopeRequest,
	})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	defer s.Close()
	go s.Serve()
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: conn.LocalAddr(), Auth: user,
		TLSConfig: client.TLSConfig{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, tc := range []struct {
		name, rule, host string
		blocked          bool
	}{
		{"TCP_control", "never-match", "allowed.example", false}, {"resolved_allow", "192.0.2.1", "allowed.example", false}, {"resolved_block", "127.0.0.1", "allowed.example", true},
		{"TCP_sniffed_domain", "blocked.example", "blocked.example", true},
		{"TCP_target_IP", "127.0.0.1", "allowed.example", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var accepts atomic.Int32
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "audit-target-reached")
			}))
			target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					accepts.Add(1)
				}
			}
			target.Start()
			defer target.Close()
			if err := l.UpdateRule(&panel.Rules{Regexp: []string{tc.rule}}); err != nil {
				t.Fatal(err)
			}
			addr := target.Listener.Addr().String()
			if strings.HasPrefix(tc.name, "resolved_") {
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort("localhost", port)
			}
			stream, err := c.TCP(addr)
			body := ""
			if err == nil {
				defer stream.Close()
				stream.SetDeadline(time.Now().Add(3 * time.Second))
				io.WriteString(stream, "GET / HTTP/1.1\r\nHost: "+tc.host+"\r\nConnection: close\r\n\r\n")
				payload, _ := io.ReadAll(stream)
				body = string(payload)
			}
			if strings.Contains(body, "audit-target-reached") == tc.blocked {
				t.Fatalf("unexpected TCP result: blocked=%v, err=%v, body=%q", tc.blocked, err, body)
			}
			if tc.blocked {
				time.Sleep(100 * time.Millisecond)
				if accepts.Load() != 0 {
					t.Fatal("rejected request opened an outbound TCP connection")
				}
			}
			records := visits.Batch()
			if len(records) != 1 || records[0].UID != 7 || records[0].Source != "127.0.0.1" || (records[0].Status == "rejected") != tc.blocked {
				t.Fatalf("unexpected visit %+v", records)
			}
			visits.Confirm(1)
		})
	}
	for _, tc := range []struct {
		name    string
		rules   panel.Rules
		blocked bool
	}{
		{"UDP_control", panel.Rules{}, false},
		{"UDP_resolved_allow", panel.Rules{Regexp: []string{"192.0.2.1"}}, false},
		{"UDP_resolved_block", panel.Rules{Regexp: []string{"127.0.0.1"}}, true},

		{"UDP_BT", panel.Rules{Protocol: []string{"bittorrent"}}, true},
		{"UDP_target_IP", panel.Rules{Regexp: []string{"127.0.0.1"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			received := make(chan []byte, 1)
			go func() {
				buffer := make([]byte, 2048)
				n, _, err := target.ReadFrom(buffer)
				if err == nil {
					received <- append([]byte(nil), buffer[:n]...)
				}
			}()
			if err := l.UpdateRule(&tc.rules); err != nil {
				t.Fatal(err)
			}
			packets, err := c.UDP()
			if err != nil {
				t.Fatal(err)
			}
			defer packets.Close()
			tracker, _ := hex.DecodeString("00000417271019800000000078e90560")
			payload := tracker
			if tc.name == "UDP_control" {
				payload = []byte("plain udp datagram")
			}
			addr := target.LocalAddr().String()
			if strings.HasPrefix(tc.name, "UDP_resolved") {
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort("localhost", port)
			}
			if err := packets.Send(payload, addr); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-received:
				if tc.blocked || !bytes.Equal(got, payload) {
					t.Fatal("unexpected UDP packet reached target")
				}
			case <-time.After(700 * time.Millisecond):
				if !tc.blocked {
					t.Fatal("allowed UDP packet was not forwarded")
				}
			}
			if tc.name == "UDP_control" {
				limit := time.Now().Add(time.Second)
				for len(visits.Batch()) == 0 && time.Now().Before(limit) {
					time.Sleep(time.Millisecond)
				}
				records := visits.Batch()
				if len(records) != 1 || records[0].Status != "accepted" {
					t.Fatalf("expected successful UDP visit, got %+v", records)
				}
				visits.Confirm(1)
				if e := l.UpdateRule(&panel.Rules{Protocol: []string{"bittorrent"}}); e != nil {
					t.Fatal(e)
				}
				e := packets.Send(tracker, target.LocalAddr().String())
				if e != nil {
					t.Fatal(e)
				}
				target.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
				buf := make([]byte, 100)
				if _, _, err := target.ReadFrom(buf); err == nil {
					t.Fatal("later blocked UDP packet reached target")
				}
				records = visits.Batch()
				if len(records) != 1 || records[0].Status != "rejected" || records[0].Hit != "protocol:bittorrent" {
					t.Fatalf("missing late rejection: %+v", records)
				}
			}
			visits.Confirm(len(visits.Batch()))

		})
	}
	if err := l.UpdateRule(&panel.Rules{}); err != nil {
		t.Fatal(err)
	}
	local := &serverConfig{}
	local.ACL.Inline = []string{"reject(127.0.0.1)"}
	outbound, err = n.getOutboundConfig(local)
	if err != nil {
		t.Fatal(err)
	}
	if stream, err := outbound.TCP("127.0.0.1:1"); err == nil {
		stream.Close()
		t.Fatal("panel audit wrapper bypassed the local ACL")
	}
}
