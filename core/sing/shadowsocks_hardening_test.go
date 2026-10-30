package sing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-mux"
	ss "github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

// Every outer socket must be TCP; this makes UoT/multiplex tests fail if they
// accidentally send the application datagrams over a native UDP socket.
type ssTestDialer struct {
	server string
	method ss.Method
	calls  int32
}

func (d *ssTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("test requires a TCP outer transport")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.server)
	if err != nil {
		return nil, err
	}
	atomic.AddInt32(&d.calls, 1)
	return d.method.DialEarlyConn(conn, destination), nil
}

func (d *ssTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("native UDP is forbidden in this transport test")
}

func TestShadowsocksCredentialCompatibility(t *testing.T) {
	const credential = "c0ffee00-0000-4000-8000-000000000007"
	for _, test := range []struct {
		method string
		length int
	}{{"aes-256-gcm", 0}, {"2022-blake3-aes-128-gcm", 16}, {"2022-blake3-aes-256-gcm", 32}} {
		want := credential
		if test.length > 0 {
			want = base64.StdEncoding.EncodeToString([]byte(credential[:test.length]))
		}
		got, err := shadowsocksUserPassword(credential, test.method)
		if err != nil || got != want {
			t.Fatalf("%s changed subscription keys: %q %v", test.method, got, err)
		}
		if test.length > 0 {
			if _, err = shadowsocksUserPassword("short", test.method); err == nil || strings.Contains(err.Error(), "short") {
				t.Fatalf("short credential must fail without exposing its value: %v", err)
			}
		}
	}
	var options conf.Options
	json.Unmarshal([]byte(`{"Core":"sing","ListenIP":"127.0.0.1"}`), &options)
	_, err := getInboundOptions("ss-invalid", &panel.NodeInfo{
		Type: "shadowsocks", Common: &panel.CommonNode{ServerPort: 443},
		Shadowsocks: &panel.ShadowsocksNode{Cipher: "2022-blake3-chacha20-poly1305"},
	}, &options)
	if err == nil || !strings.Contains(err.Error(), "multi-user") {
		t.Fatalf("unsupported multi-user method: %v", err)
	}
}

func TestShadowsocksTCPOptions(t *testing.T) {
	info := &panel.NodeInfo{Type: "shadowsocks", Common: &panel.CommonNode{ServerPort: 443}, Shadowsocks: &panel.ShadowsocksNode{Cipher: "aes-128-gcm"}}
	var config conf.Options
	if err := json.Unmarshal([]byte(`{"Core":"sing","ListenIP":"127.0.0.1","ShadowsocksConfig":{"HandshakeTimeout":7,"TrafficShaping":{"Enable":true,"MinRecordSize":256,"MaxRecordSize":1024,"MinRecords":4,"MaxRecords":9}}}`), &config); err != nil {
		t.Fatal(err)
	}
	in, err := getInboundOptions("ss-options", info, &config)
	if err != nil {
		t.Fatal(err)
	}
	settings := in.Options.(*option.ShadowsocksInboundOptions)
	if time.Duration(settings.HandshakeTimeout) != 7*time.Second || settings.TrafficShaping == nil || !settings.TrafficShaping.Enabled || settings.TrafficShaping.MinRecordSize != 256 || settings.TrafficShaping.MaxRecordSize != 1024 || settings.TrafficShaping.MinRecords != 4 || settings.TrafficShaping.MaxRecords != 9 {
		t.Fatalf("TCP options were not passed through: %+v", settings)
	}
}

// Use sing-shadowsocks2, the independent implementation used by sing-box's
// outbound, against the legacy inbound library through V2bX's actual listener.
func TestShadowsocksClientCompatibilityAndUserRemoval(t *testing.T) {
	limiter.Init()
	core, err := New(&conf.CoreConfig{Type: "sing", SingConfig: conf.NewSingConfig()})
	if err != nil {
		t.Fatal(err)
	}
	s := core.(*Sing)
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tcpEcho := startEchoServer(t)
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		p := make([]byte, 65535)
		for {
			n, addr, err := udpEcho.ReadFrom(p)
			if err != nil {
				return
			}
			udpEcho.WriteTo(p[:n], addr)
		}
	}()

	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			users := []panel.UserInfo{
				{Id: 101, Uuid: "11111111-1111-4111-8111-111111111111"},
				{Id: 102, Uuid: "22222222-2222-4222-8222-222222222222"},
			}
			port := freeTCPPort(t)
			keyLength := 32
			if method == "2022-blake3-aes-128-gcm" {
				keyLength = 16
			}
			serverKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, keyLength))
			info := &panel.NodeInfo{Type: "shadowsocks", Shadowsocks: &panel.ShadowsocksNode{Cipher: method, ServerKey: serverKey}}
			info.Common = &info.Shadowsocks.CommonNode
			info.Common.ServerPort = port
			var options conf.Options
			if err := json.Unmarshal([]byte(`{"Core":"sing","ListenIP":"127.0.0.1",
				"ShadowsocksConfig":{"HandshakeTimeout":2,"TrafficShaping":{"Enable":true},"UDPPadding":{"Enable":true}},
				"MultiplexConfig":{"Enable":true,"Padding":false}}`), &options); err != nil {
				t.Fatal(err)
			}
			tag := "ss-compat-" + method
			if err := s.AddNode(tag, info, &options); err != nil {
				t.Fatal(err)
			}
			defer s.DelNode(tag)
			limiter.AddLimiter(tag, &conf.LimitConfig{}, users, nil)
			defer limiter.DeleteLimiter(tag)
			if strings.HasPrefix(method, "2022-") {
				batch := []panel.UserInfo{users[0], {Id: 103, Uuid: "short"}}
				if _, err := s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: batch, NodeInfo: info}); err == nil {
					t.Fatal("invalid credential accepted")
				}
				s.users.mapLock.RLock()
				_, invalid := s.users.uidMap["short"]
				s.users.mapLock.RUnlock()
				if invalid {
					t.Fatal("failed batch changed user accounting")
				}
			}
			if _, err := s.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
				t.Fatal(err)
			}
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			client := func(user panel.UserInfo) ss.Method {
				password, err := shadowsocksUserPassword(user.Uuid, method)
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(method, "2022-") {
					password = serverKey + ":" + password
				}
				m, err := ss.CreateMethod(context.Background(), method, ss.MethodOptions{Password: password})
				if err != nil {
					t.Fatal(err)
				}
				return m
			}
			dial := func(user panel.UserInfo) net.Conn {
				wire, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				c := client(user).DialEarlyConn(wire, M.ParseSocksaddr(tcpEcho))
				t.Cleanup(func() { c.Close() })
				return c
			}
			echo := func(c net.Conn) {
				c.SetDeadline(time.Now().Add(3 * time.Second))
				payload := bytes.Repeat([]byte("ss-client-compatibility"), 3000)
				if _, err := c.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("TCP echo: %v", err)
				}
			}
			first, second := dial(users[0]), dial(users[1])
			echo(first)
			echo(second)
			udpWire, err := net.Dial("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			packets := client(users[1]).DialPacketConn(udpWire)
			defer packets.Close()
			udpRoundTrip := func() {
				for _, size := range []int{1, 17, 1100, 1200, 1400} {
					payload := bytes.Repeat([]byte{0x5a}, size)
					packets.SetDeadline(time.Now().Add(3 * time.Second))
					if _, err := packets.WriteTo(payload, udpEcho.LocalAddr()); err != nil {
						t.Fatal(err)
					}
					p := make([]byte, 65535)
					n, _, err := packets.ReadFrom(p)
					if err != nil || !bytes.Equal(p[:n], payload) {
						t.Fatalf("UDP echo size %d: %v", size, err)
					}
				}
			}
			udpRoundTrip()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			outer := &ssTestDialer{server: addr, method: client(users[1])}
			multiplex, err := mux.NewClient(mux.Options{Dialer: outer, Logger: logger.NOP(), Protocol: "h2mux", Padding: true})
			if err != nil {
				t.Fatal(err)
			}
			defer multiplex.Close()
			for i := 0; i < 2; i++ {
				stream, err := multiplex.DialContext(ctx, "tcp", M.ParseSocksaddr(tcpEcho))
				if err != nil {
					t.Fatal(err)
				}
				echo(stream)
				stream.Close()
			}
			udpEchoThroughTCP := func(p net.PacketConn) {
				t.Helper()
				defer p.Close()
				p.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := p.WriteTo([]byte("UDP over a TCP tunnel"), udpEcho.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 1024)
				n, _, err := p.ReadFrom(got)
				if err != nil || string(got[:n]) != "UDP over a TCP tunnel" {
					t.Fatalf("UDP over TCP: %v", err)
				}
			}
			muxPackets, err := multiplex.ListenPacket(ctx, M.ParseSocksaddr(udpEcho.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			udpEchoThroughTCP(muxPackets)
			if calls := atomic.LoadInt32(&outer.calls); calls != 1 {
				t.Fatalf("streams did not reuse their TCP session: %d", calls)
			}
			for _, version := range []uint8{1, 2} {
				uotClient := &uot.Client{Dialer: outer, Version: version}
				p, err := uotClient.ListenPacket(ctx, M.ParseSocksaddr(udpEcho.LocalAddr().String()))
				if err != nil {
					t.Fatal(err)
				}
				udpEchoThroughTCP(p)
			}
			if err := s.DelUsers(users[:1], tag, info); err != nil {
				t.Fatal(err)
			}
			first.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := first.Read(make([]byte, 1)); err == nil {
				t.Fatal("removed user's connection is still open")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("removed user's connection was not closed promptly")
			}
			echo(second)
			udpRoundTrip()
			echo(dial(users[1]))
			if up, down := s.GetUserTraffic(tag, users[1].Uuid, false); up == 0 || down == 0 {
				t.Fatalf("surviving user lost traffic attribution: %d/%d", up, down)
			}
		})
	}
}

func TestShadowsocksUDPPaddingOnlyAppliesToSS2022(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		var config conf.Options
		if err := json.Unmarshal([]byte(`{"Core":"sing","ListenIP":"127.0.0.1","ShadowsocksConfig":{"UDPPadding":{"Enable":true,"MaxPacketSize":1280,"MaxPaddingBytes":512}}}`), &config); err != nil {
			t.Fatal(err)
		}
		info := &panel.NodeInfo{Type: "shadowsocks", Common: &panel.CommonNode{ServerPort: 443}, Shadowsocks: &panel.ShadowsocksNode{Cipher: method}}
		in, err := getInboundOptions("ss-udp-options", info, &config)
		if err != nil {
			t.Fatal(err)
		}
		settings := in.Options.(*option.ShadowsocksInboundOptions)
		if method == "aes-128-gcm" {
			if settings.UDPPadding != nil {
				t.Fatal("legacy AEAD was given an unsupported padding policy")
			}
		} else if settings.UDPPadding == nil || !settings.UDPPadding.Enabled || settings.UDPPadding.MaxPacketSize != 1280 || settings.UDPPadding.MaxPaddingBytes != 512 {
			t.Fatalf("UDP padding options were not passed through: %+v", settings)
		}
	}
}
