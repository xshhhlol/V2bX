package dispatcher

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

type compatibilitySniffResult string

func (compatibilitySniffResult) Protocol() string { return "tls" }
func (r compatibilitySniffResult) Domain() string { return string(r) }

func TestXrayDispatcherExclusions(t *testing.T) {
	config := coreConf.SniffingConfig{
		Enabled: true, DestOverride: coreConf.StringList{"tls"},
		DomainsExcluded: coreConf.StringList{"full:excluded.example", `regexp:^private\.`},
		IPsExcluded:     coreConf.StringList{"192.0.2.0/24"},
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	request, err := proxyman.BuildSniffingRequest(built)
	if err != nil {
		t.Fatal(err)
	}
	d := &DefaultDispatcher{}
	for _, tc := range []struct {
		domain, ip string
		want       bool
	}{
		{"EXCLUDED.EXAMPLE", "198.51.100.1", false},
		{"private.example", "198.51.100.1", false},
		{"public.example", "192.0.2.10", false},
		{"public.example", "198.51.100.1", true},
		{"", "198.51.100.1", false},
	} {
		destination := net.TCPDestination(net.ParseAddress(tc.ip), 443)
		if got := d.shouldOverride(context.Background(), compatibilitySniffResult(tc.domain), request, destination); got != tc.want {
			t.Errorf("domain=%s ip=%s: override=%v, want %v", tc.domain, tc.ip, got, tc.want)
		}
	}
}

type compatibilityLink struct{ closed atomic.Bool }

func (l *compatibilityLink) Close() error                            { l.closed.Store(true); return nil }
func (l *compatibilityLink) Interrupt()                              { l.closed.Store(true) }
func (*compatibilityLink) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, io.EOF }
func (*compatibilityLink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func TestXrayLinkManagerRevocation(t *testing.T) {
	m := &LinkManager{links: make(map[*ManagedWriter]buf.Reader)}
	var workers sync.WaitGroup
	var connections []*compatibilityLink
	start := make(chan struct{})
	for range 32 {
		writer, reader := &compatibilityLink{}, &compatibilityLink{}
		connections = append(connections, writer, reader)
		workers.Go(func() {
			<-start
			m.AddLink(&ManagedWriter{writer: writer, manager: m}, reader)
		})
	}
	workers.Go(func() { <-start; m.CloseAll() })
	close(start)
	workers.Wait()
	for _, c := range connections {
		if !c.closed.Load() {
			t.Fatal("connection survived user revocation")
		}
	}
}
