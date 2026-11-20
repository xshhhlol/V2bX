package sing

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/InazumaV/V2bX/common/auditpacket"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (h *HookServer) PrepareAudit(ctx context.Context, m *adapter.InboundContext) error {
	if m.Fallback {
		return nil
	}
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		return err
	}
	return h.pinDestination(ctx, l, m)
}

func (h *HookServer) pinDestination(ctx context.Context, l *limiter.Limiter, m *adapter.InboundContext) error {
	if !l.HasIPRules() || !m.Destination.IsDomain() {
		return nil
	}
	addresses := m.DestinationAddresses
	if len(addresses) == 0 {
		var err error
		addresses, err = h.dns.Lookup(adapter.WithContext(ctx, m), m.Destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return err
		}
	}
	if len(addresses) == 0 {
		return fmt.Errorf("no audited address for %s", m.Destination)
	}
	for _, ip := range addresses {
		if hit, ok := l.IPHit(ip); ok {
			l.RecordVisit(m.Inbound, m.User, m.Source.Addr.String(), m.Destination.String(), m.Domain, hit)
			return fmt.Errorf("resolved target %s blocked by panel", ip)
		}
	}
	if !m.RouteOriginalDestination.IsValid() {
		m.RouteOriginalDestination = m.Destination
	}
	m.DestinationAddresses = addresses
	m.Destination = M.SocksaddrFrom(addresses[0], m.Destination.Port)
	return nil
}

type visitConn struct {
	net.Conn
	metadata adapter.InboundContext
	limiter  *limiter.Limiter
}

func (c *visitConn) Upstream() any           { return c.Conn }
func (c *visitConn) ReaderReplaceable() bool { return true }
func (c *visitConn) WriterReplaceable() bool { return true }
func (c *visitConn) ConnHandshakeSuccess(remote net.Conn) error {
	if err := N.ReportConnHandshakeSuccess(c.Conn, remote); err != nil {
		return err
	}
	m := c.metadata
	c.limiter.RecordVisit(m.Inbound, m.User, m.Source.Addr.String(), m.Destination.String(), m.Domain, limiter.RuleHit{})
	return nil
}

type auditPacketWriter struct {
	names     limiter.DestinationCache
	inspect   auditpacket.Inspector
	dialed    netip.Addr
	connected bool
	N.PacketConn
	association *auditPacketConn
	lastAddress M.Socksaddr
	lastDomain  string
}

func (c *auditPacketConn) AuditPacketWriter(remote N.PacketConn, dialed netip.Addr, connected bool) N.PacketConn {
	return &auditPacketWriter{PacketConn: remote, association: c, dialed: dialed, connected: connected}
}

func (c *auditPacketWriter) Upstream() any           { return c.PacketConn }
func (c *auditPacketWriter) ReaderReplaceable() bool { return true }
func (c *auditPacketWriter) WriterReplaceable() bool { return false }
func (c *auditPacketWriter) WritePacket(b *buf.Buffer, d M.Socksaddr) error {
	a := c.association
	l := a.limiter
	m := a.metadata
	if m.Destination != d {
		m.DestinationAddresses = nil
		m.Domain = ""
		m.Protocol = ""
		m.RouteOriginalDestination = M.Socksaddr{}
	}
	m.Destination = d
	if l.NeedsSniff() || l.WatchesVisits() {
		domain, proto := c.inspect.Inspect(d, b.Bytes(), l.HasProtocolRules())
		if domain != "" {
			m.Domain = domain
		}
		if proto != "" {
			m.Protocol = proto
		}
		var hit limiter.RuleHit
		// Raw destinations were checked by ReadPacket. Only a sniffed name
		// adds destination candidates; cache that decision per association.
		if m.Domain != "" {
			if matched, denied := c.names.Check(l, "udp", d.String(), m.Domain); denied {
				hit = matched
			}
		}
		if hit.Label == "" {
			hit, _ = l.ProtocolHit(m.Protocol)
		}
		if hit.Label != "" {
			l.RecordVisit(m.Inbound, m.User, m.Source.Addr.String(), d.String(), m.Domain, hit)
			b.Release()
			return fmt.Errorf("UDP payload blocked by panel rule %s", hit.Label)
		}
	}
	// Connected UDP and the initial destination NAT may keep the address
	// selected when the socket was opened even after a DNS or rule update.
	if c.dialed.IsValid() && (c.connected || d == a.metadata.Destination) {
		if hit, ok := l.IPHit(c.dialed); ok {
			l.RecordVisit(m.Inbound, m.User, m.Source.Addr.String(), d.String(), m.Domain, hit)
			b.Release()
			return fmt.Errorf("UDP destination %s blocked by panel", c.dialed)
		}
	} else if err := a.hook.pinDestination(a.ctx, l, &m); err != nil {
		b.Release()
		return err
	}
	if err := c.PacketConn.WritePacket(b, m.Destination); err != nil {
		return err
	}
	if d != c.lastAddress || m.Domain != c.lastDomain {
		l.RecordVisit(m.Inbound, m.User, m.Source.Addr.String(), d.String(), m.Domain, limiter.RuleHit{})
		c.lastAddress, c.lastDomain = d, m.Domain
	}
	return nil
}
