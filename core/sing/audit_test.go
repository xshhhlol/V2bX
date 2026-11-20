package sing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	anytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/option"
	tuicout "github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type auditTestPacketConn struct {
	N.PacketConn
	destinations []M.Socksaddr
	closed       bool
}

func (c *auditTestPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination := c.destinations[0]
	c.destinations = c.destinations[1:]
	buffer.WriteString("test-packet")
	return destination, nil
}

func (c *auditTestPacketConn) Close() error { c.closed = true; return nil }

func TestAuditPacketDestinationChange(t *testing.T) {
	l := &limiter.Limiter{}
	if err := l.UpdateRule(&panel.Rules{Regexp: []string{"203.0.113.2"}}); err != nil {
		t.Fatal(err)
	}
	underlying := &auditTestPacketConn{destinations: []M.Socksaddr{
		M.ParseSocksaddr("203.0.113.1:443"), M.ParseSocksaddr("203.0.113.2:443"),
	}}
	conn := &auditPacketConn{PacketConn: underlying, limiter: l, user: "test"}
	buffer := buf.NewPacket()
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); err != nil {
		t.Fatal(err)
	}
	buffer.Reset()
	if _, err := conn.ReadPacket(buffer); err == nil || !underlying.closed {
		t.Fatal("a later forbidden destination was accepted in the same UDP association")
	}
}

func TestAuditPacketRuleRefresh(t *testing.T) {
	l := &limiter.Limiter{}
	destination := M.ParseSocksaddr("203.0.113.1:443")
	underlying := &auditTestPacketConn{destinations: []M.Socksaddr{destination, destination}}
	conn := &auditPacketConn{PacketConn: underlying, limiter: l, user: "test"}
	buffer := buf.NewPacket()
	defer buffer.Release()
	if _, err := conn.ReadPacket(buffer); err != nil {
		t.Fatal(err)
	}
	if err := l.UpdateRule(&panel.Rules{Regexp: []string{"203.0.113.1"}}); err != nil {
		t.Fatal(err)
	}
	buffer.Reset()
	if _, err := conn.ReadPacket(buffer); err == nil || !underlying.closed {
		t.Fatal("an existing UDP association kept its cached allow after rule refresh")
	}
}

func TestAuditProtocols(t *testing.T) {
	for _, typ := range []string{"anytls", "tuic"} {
		t.Run(typ, func(t *testing.T) {
			limiter.Init()
			tag := "audit-real-" + typ
			user := panel.UserInfo{Id: 1, Uuid: "c0ffee00-0000-4000-8000-000000000001"}
			cert, key := writeTestCertificate(t)
			original := filepath.Join(t.TempDir(), "origin.json")
			origin := []byte(`{"dns":{"servers":[{"type":"hosts","tag":"hosts","predefined":{"target.example":"127.0.0.1"}}]},"route":{"rules":[{"action":"sniff"}]}}`)
			if typ == "anytls" {
				origin = bytes.ReplaceAll(origin, []byte(`{"action":"sniff"}`), nil)
			}
			os.WriteFile(original, origin, 0600)
			sc := conf.NewSingConfig()
			sc.OriginalPath = original
			sc.LogConfig.Level = "debug"
			vc, e := New(&conf.CoreConfig{Type: "sing", SingConfig: sc})
			if e != nil {
				t.Fatal(e)
			}
			s := vc.(*Sing)
			if e = s.Start(); e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			port := freeTCPPort(t)
			var opts conf.Options
			e = json.Unmarshal([]byte(fmt.Sprintf(`{"Core":"sing","ListenIP":"127.0.0.1","CertConfig":{"CertMode":"file","CertFile":%q,"KeyFile":%q}}`, cert, key)), &opts)
			if e != nil {
				t.Fatal(e)
			}
			info := &panel.NodeInfo{Type: typ, Security: panel.Tls, Common: &panel.CommonNode{ServerPort: port}, AnyTls: &panel.AnyTlsNode{}, Tuic: &panel.TuicNode{CongestionControl: "cubic"}}
			l := limiter.AddLimiter(tag, &conf.LimitConfig{}, []panel.UserInfo{user}, nil)
			var visits limiter.VisitMonitor
			if err := visits.Update(&panel.VisitRules{Suffixes: []string{"allowed.example", "127.0.0.1"}}); err != nil {
				t.Fatal(err)
			}
			l.SetVisits(&visits)
			defer limiter.DeleteLimiter(tag)
			if e = s.AddNode(tag, info, &opts); e != nil {
				t.Fatal(e)
			}
			defer s.DelNode(tag)
			if _, e = s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: []panel.UserInfo{user}, NodeInfo: info}); e != nil {
				t.Fatal(e)
			}
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			var dial func(context.Context, M.Socksaddr) (net.Conn, error)
			var listenPacket func(context.Context, M.Socksaddr) (net.PacketConn, error)
			if typ == "anytls" {
				client, e := anytls.NewClient(anytls.ClientOptions{Password: user.Uuid, DialOut: func(ctx context.Context) (net.Conn, error) {
					d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
					return d.DialContext(ctx, "tcp", addr)
				}})
				if e != nil {
					t.Fatal(e)
				}
				defer client.Close()
				dial = client.DialContext
			} else {
				ob, e := tuicout.NewOutbound(s.ctx, s.router, s.logFactory.NewLogger("audit-client"), "audit-client", option.TUICOutboundOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(port)}, UUID: user.Uuid, Password: user.Uuid, CongestionControl: "cubic", OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ALPN: []string{"h3"}}}})
				if e != nil {
					t.Fatal(e)
				}
				defer ob.(*tuicout.Outbound).InterfaceUpdated(context.Background())
				listenPacket = ob.ListenPacket
				dial = func(ctx context.Context, d M.Socksaddr) (net.Conn, error) { return ob.DialContext(ctx, "tcp", d) }
			}
			for _, tc := range []struct {
				name, rule, host string
				wantReply        bool
			}{{"control", `^never-match$`, "allowed.example", true}, {"resolved_allow", "192.0.2.1", "allowed.example", true}, {"resolved_block", "127.0.0.1", "allowed.example", false}, {"IP_target_sniffed_domain_block", `^blocked\.example$`, "blocked.example", false}, {"matched_rule_stops_before_dial", `^127\.0\.0\.1$`, "blocked.example", false}} {
				t.Run(tc.name, func(t *testing.T) {
					var accepts atomic.Int32
					var requests atomic.Int32
					target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						io.WriteString(w, "audit-target-reached")
					}))
					target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
						if state == http.StateNew {
							accepts.Add(1)
						}
					}
					target.Start()
					defer target.Close()
					l.UpdateRule(&panel.Rules{Regexp: []string{tc.rule}})
					ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
					defer cancel()
					destination := M.ParseSocksaddr(target.Listener.Addr().String())
					if strings.HasPrefix(tc.name, "resolved_") {
						destination = M.Socksaddr{Fqdn: "target.example", Port: destination.Port}
					}
					conn, e := dial(ctx, destination)
					body := ""
					if e == nil {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						_, e = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+tc.host+"\r\nConnection: close\r\n\r\n")
						if e == nil {
							b, err := io.ReadAll(conn)
							body = string(b)
							e = err
						}
					}
					replied := strings.Contains(body, "audit-target-reached")
					if replied != tc.wantReply {
						t.Fatalf("reply=%v want=%v err=%v body=%q", replied, tc.wantReply, e, body)
					}
					if !tc.wantReply {
						time.Sleep(100 * time.Millisecond)
						if accepts.Load() != 0 {
							t.Fatalf("rejected target still received %d TCP connections", accepts.Load())
						}
					}
					records := visits.Batch()
					if len(records) != 1 || records[0].UID != user.Id || records[0].Source != "127.0.0.1" || (records[0].Status == "accepted") != tc.wantReply {
						t.Fatalf("unexpected visit %+v", records)
					}
					visits.Confirm(1)
					t.Logf("OBSERVED %s: target accepted=%d HTTP requests=%d HTTP reply=%v client err=%v", typ, accepts.Load(), requests.Load(), replied, e)
				})
			}

			if typ == "tuic" {
				for _, tc := range []struct {
					name    string
					rules   panel.Rules
					blocked bool
				}{
					{"UDP_control", panel.Rules{}, false},
					{"UDP_resolved_allow", panel.Rules{Regexp: []string{"192.0.2.1"}}, false},
					{"UDP_resolved_block", panel.Rules{Regexp: []string{"127.0.0.1"}}, true},

					{"UDP_BT_block", panel.Rules{Protocol: []string{"bittorrent"}}, true},
					{"UDP_target_block", panel.Rules{Regexp: []string{`regexp:^127\.0\.0\.1$`}}, true},
				} {
					t.Run(tc.name, func(t *testing.T) {
						target, e := net.ListenPacket("udp", "127.0.0.1:0")
						if e != nil {
							t.Fatal(e)
						}
						defer target.Close()
						received := make(chan []byte, 1)
						go func() {
							b := make([]byte, 2048)
							n, _, e := target.ReadFrom(b)
							if e == nil {
								received <- append([]byte(nil), b[:n]...)
							}
						}()
						if e = l.UpdateRule(&tc.rules); e != nil {
							t.Fatal(e)
						}
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						destination := M.ParseSocksaddr(target.LocalAddr().String())
						if strings.HasPrefix(tc.name, "UDP_resolved") {
							destination = M.Socksaddr{Fqdn: "target.example", Port: destination.Port}
						}
						c, e := listenPacket(ctx, destination)
						if e != nil {
							t.Fatal(e)
						}
						defer c.Close()
						tracker, _ := hex.DecodeString("00000417271019800000000078e90560")
						payload := tracker
						if tc.name == "UDP_control" {
							payload = []byte("plain udp datagram")
						}
						if _, e = c.WriteTo(payload, destination); e != nil {
							t.Fatal(e)
						}
						select {
						case got := <-received:
							if tc.blocked {
								t.Fatal("blocked UDP packet reached target")
							}
							if !bytes.Equal(got, payload) {
								t.Fatal("UDP payload changed")
							}
						case <-time.After(700 * time.Millisecond):
							if !tc.blocked {
								t.Fatal("allowed UDP packet did not reach target")
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
							_, e = c.WriteTo(tracker, target.LocalAddr())
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
			}
		})
	}
}
