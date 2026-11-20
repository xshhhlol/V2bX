package sing

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/common/rate"

	"github.com/InazumaV/V2bX/limiter"

	"github.com/InazumaV/V2bX/common/counter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*HookServer)(nil)

type HookServer struct {
	dns     adapter.DNSRouter
	counter sync.Map //map[string]*counter.TrafficCounter
}

func (h *HookServer) ModeList() []string {
	return nil
}

func (h *HookServer) RoutedConnection(ctx context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	// Fallback connections carry no user and go to the configured site,
	// so they bypass user limits and traffic accounting.
	if m.Fallback {
		return conn
	}
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		conn.Close()
		return nil
	}
	taguuid := format.UserTag(m.Inbound, m.User)
	ip := m.Source.Addr.String()
	if b, r := l.CheckLimit(taguuid, ip, true, true); r {
		conn.Close()
		log.Error("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return nil
	} else if b != nil {
		conn = rate.NewConnRateLimiter(conn, b)
	}
	// Existing installs can have no sniff action. Preserve any consumed bytes
	// and avoid repeating a sniff already attempted by the router.
	if (l.NeedsSniff() || l.WatchesVisits()) && m.Protocol == "" && m.SniffError == nil && !sniff.Skip(&m) {
		buffer := buf.NewPacket()
		_ = sniff.PeekStream(ctx, &m, conn, nil, buffer, 0, sniff.TLSClientHello, sniff.HTTPHost, sniff.StreamDomainNameQuery, sniff.BitTorrent, sniff.SSH, sniff.RDP)
		if buffer.IsEmpty() {
			buffer.Release()
		} else {
			conn = bufio.NewCachedConn(conn, buffer)
		}
	}
	if rejectRule(l, m) {
		conn.Close()
		return nil
	}
	var t *counter.TrafficCounter
	if c, ok := h.counter.Load(m.Inbound); !ok {
		t = counter.NewTrafficCounter()
		h.counter.Store(m.Inbound, t)
	} else {
		t = c.(*counter.TrafficCounter)
	}
	if l.WatchesVisits() {
		conn = &visitConn{Conn: conn, metadata: m, limiter: l}
	}
	conn = counter.NewConnCounter(conn, t.GetCounter(m.User))
	return conn
}

func (h *HookServer) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		conn.Close()
		return nil
	}
	ip := m.Source.Addr.String()
	taguuid := format.UserTag(m.Inbound, m.User)
	if b, r := l.CheckLimit(taguuid, ip, false, false); r {
		conn.Close()
		log.Error("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return nil
	} else if b != nil {
		//conn = rate.NewPacketConnCounter(conn, b)
	}
	if rejectRule(l, m) {
		conn.Close()
		return nil
	}
	// TUIC and UoT associations may carry packets to multiple destinations.
	// Checking only the association's initial target would miss later targets.
	conn = &auditPacketConn{PacketConn: conn, limiter: l, user: m.User, metadata: m, ctx: ctx, hook: h}
	var t *counter.TrafficCounter
	if c, ok := h.counter.Load(m.Inbound); !ok {
		t = counter.NewTrafficCounter()
		h.counter.Store(m.Inbound, t)
	} else {
		t = c.(*counter.TrafficCounter)
	}
	conn = counter.NewPacketConnCounter(conn, t.GetCounter(m.User))
	return conn
}

func rejectRule(l *limiter.Limiter, m adapter.InboundContext) bool {
	for _, address := range []M.Socksaddr{m.Destination, m.RouteOriginalDestination} {
		if !address.IsValid() {
			continue
		}
		if destination, rejected := l.CheckDestinationRule(m.Network, address.String(), m.Domain); rejected {
			l.RecordVisit(m.Inbound, m.User, m.Source.Addr.String(), address.String(), m.Domain, destination)
			log.Error(fmt.Sprintf("User %s access domain %s reject by rule", m.User, destination.Label))
			return true
		}
	}
	if hit, ok := l.ProtocolHit(m.Protocol); ok {
		l.RecordVisit(m.Inbound, m.User, m.Source.Addr.String(), m.Destination.String(), m.Domain, hit)
		log.Error(fmt.Sprintf("User %s access protocol %s reject by rule", m.User, m.Protocol))
		return true
	}
	return false
}

type auditPacketConn struct {
	ctx      context.Context
	metadata adapter.InboundContext
	hook     *HookServer
	N.PacketConn
	limiter *limiter.Limiter
	user    string
	cache   limiter.DestinationCache
}

// Expose writer metadata (notably SS/SS2022 packet headroom), while keeping
// ReadPacket non-replaceable so optimized copy paths cannot bypass the audit.
func (c *auditPacketConn) Upstream() any           { return c.PacketConn }
func (c *auditPacketConn) ReaderReplaceable() bool { return false }
func (c *auditPacketConn) WriterReplaceable() bool { return true }

func (c *auditPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err != nil {
		return destination, err
	}
	if matched, rejected := c.cache.Check(c.limiter, "udp", destination.String(), ""); rejected {
		c.limiter.RecordVisit(c.metadata.Inbound, c.user, c.metadata.Source.Addr.String(), destination.String(), "", matched)
		c.Close()
		return destination, fmt.Errorf("user %s access domain %s rejected by rule", c.user, destination.AddrString())
	}
	return destination, err
}

// RoutedFlow tracks L3 flows (TUN, WireGuard and Tailscale forwarding), which V2bX nodes do not use.
func (h *HookServer) RoutedFlow(_ context.Context, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) tun.FlowTracker {
	return nil
}
