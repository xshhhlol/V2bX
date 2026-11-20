package hy2

import (
	"context"
	"errors"
	"fmt"
	"github.com/InazumaV/V2bX/common/auditpacket"
	"net"
	"strings"
	"time"

	"github.com/InazumaV/V2bX/limiter"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// The outbound guard also checks later UDP destinations in a full-cone session.
// A request hook alone only sees the session's initial destination.
type auditOutbound struct {
	visit *requestVisit
	server.Outbound
	tag string
}

func auditDestination(tag, network, address string) error {
	return auditCachedDestination(tag, network, address, nil)
}

func auditCachedDestination(tag, network, address string, cache *limiter.DestinationCache) error {
	l, err := limiter.GetLimiter(tag)
	if err != nil {
		return fmt.Errorf("audit limiter: %w", err)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return err
	}
	var target limiter.RuleHit
	var rejected bool
	if cache != nil {
		target, rejected = cache.Check(l, network, address, "")
	} else {
		target, rejected = l.CheckDestinationRule(network, address, "")
	}
	if rejected {
		return policyBlock{target}
	}
	return nil
}

func (o *auditOutbound) TCP(address string) (net.Conn, error) {
	if err := auditDestination(o.tag, "tcp", address); err != nil {
		o.visit.record(address, "", err)
		return nil, err
	}
	conn, err := o.Outbound.TCP(address)
	o.visit.record(address, "", err)
	return conn, err
}

func (o *auditOutbound) UDP(address string) (server.UDPConn, error) {
	if err := auditDestination(o.tag, "udp", address); err != nil {
		o.visit.record(address, "", err)
		return nil, err
	}
	conn, err := o.Outbound.UDP(address)
	if err != nil {
		o.visit.record(address, "", err)
		return nil, err
	}
	return &auditUDPConn{UDPConn: conn, tag: o.tag, visit: o.visit}, nil
}

func (o *auditOutbound) CheckUDP(address string) error {
	if err := auditDestination(o.tag, "udp", address); err != nil {
		o.visit.record(address, "", err)
		return err
	}
	err := o.Outbound.CheckUDP(address)
	if err != nil {
		o.visit.record(address, "", err)
	}
	return err
}

type auditUDPConn struct {
	inspect                 auditpacket.Inspector
	visit                   *requestVisit
	lastAddress, lastDomain string
	server.UDPConn
	tag   string
	cache limiter.DestinationCache
	names limiter.DestinationCache
}

func (c *auditUDPConn) WriteTo(payload []byte, address string) (int, error) {
	if err := auditCachedDestination(c.tag, "udp", address, &c.cache); err != nil {
		c.visit.record(address, "", err)
		return 0, err
	}
	l, err := limiter.GetLimiter(c.tag)
	if err != nil {
		return 0, err
	}
	var domain, proto string
	if l.NeedsSniff() || l.WatchesVisits() {
		domain, proto = c.inspect.Inspect(M.ParseSocksaddr(address), payload, l.HasProtocolRules())
	}
	var hit limiter.RuleHit
	if domain != "" {
		if matched, denied := c.names.Check(l, "udp", address, domain); denied {
			hit = matched
		}
	}
	if hit.Label == "" {
		hit, _ = l.ProtocolHit(proto)
	}
	if hit.Label != "" {
		err := policyBlock{hit}
		c.visit.record(address, domain, err)
		return 0, err
	}
	n, err := c.UDPConn.WriteTo(payload, address)
	if err != nil || address != c.lastAddress || domain != "" && domain != c.lastDomain {
		c.visit.record(address, domain, err)
		if err == nil {
			c.lastAddress, c.lastDomain = address, domain
		}
	}
	return n, err
}

type auditRequestHook struct {
	visit   *requestVisit
	tag     string
	next    server.RequestHook
	timeout time.Duration
}

func (h *auditRequestHook) Check(isUDP bool, address string) bool {
	if strings.HasPrefix(address, "@") {
		return false // Hysteria's internal requests are not proxy destinations.
	}
	l, err := limiter.GetLimiter(h.tag)
	return err != nil || l.NeedsSniff() || l.WatchesVisits() || h.next != nil && h.next.Check(isUDP, address)
}

func (h *auditRequestHook) TCP(stream server.HyStream, address *string) ([]byte, error) {
	if err := auditDestination(h.tag, "tcp", *address); err != nil {
		h.visit.record(*address, "", err)
		return nil, err
	}
	l, err := limiter.GetLimiter(h.tag)
	if err != nil {
		return nil, err
	}
	if !l.NeedsSniff() && !l.WatchesVisits() {
		if h.next != nil && h.next.Check(false, *address) {
			return h.next.TCP(stream, address)
		}
		return nil, nil
	}
	metadata := adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddr(*address)}
	if sniff.Skip(&metadata) {
		return nil, nil
	}
	buffer := buf.NewPacket()
	defer buffer.Release()
	err = sniff.PeekStream(context.Background(), &metadata, auditStream{stream}, nil, buffer, h.timeout,
		sniff.TLSClientHello, sniff.HTTPHost, sniff.StreamDomainNameQuery, sniff.BitTorrent, sniff.SSH, sniff.RDP)
	if buffer.IsEmpty() && err != nil {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			return nil, err
		}
	}
	if h.visit != nil {
		h.visit.domain = metadata.Domain
		h.visit.address = *address
	}
	if err := checkSniffedRule(l, metadata); err != nil {
		h.visit.record(*address, metadata.Domain, err)
		return nil, err
	}
	// Audit the sniffed name without changing the actual destination. Preserve
	// address rewriting only when the existing sniff configuration requests it.
	if h.next != nil && h.next.Check(false, *address) && M.IsDomainName(metadata.Domain) {
		_, port, _ := net.SplitHostPort(*address)
		*address = net.JoinHostPort(metadata.Domain, port)
	}
	return append([]byte(nil), buffer.Bytes()...), nil
}

func (h *auditRequestHook) UDP(packets [][]byte, address *string) (bool, error) {
	if err := auditDestination(h.tag, "udp", *address); err != nil {
		h.visit.record(*address, "", err)
		return true, err
	}
	l, err := limiter.GetLimiter(h.tag)
	if err != nil {
		return true, err
	}
	if l.NeedsSniff() || l.WatchesVisits() {
		metadata := adapter.InboundContext{Network: "udp", Destination: M.ParseSocksaddr(*address)}
		var err error
		for _, packet := range packets {
			err = sniff.PeekPacket(context.Background(), &metadata, packet,
				sniff.DomainNameQuery, sniff.QUICClientHello, sniff.STUNMessage, sniff.UTP, sniff.UDPTracker, sniff.DTLSRecord, sniff.NTP)
			if err == nil {
				break
			}
		}
		if h.visit != nil {
			h.visit.domain = metadata.Domain
			h.visit.address = *address
		}
		if err := checkSniffedRule(l, metadata); err != nil {
			h.visit.record(*address, metadata.Domain, err)
			return true, err
		}
		if errors.Is(err, sniff.ErrNeedMoreData) && len(packets) < 8 {
			return false, nil
		}
	}
	if h.next != nil && h.next.Check(true, *address) {
		return h.next.UDP(packets, address)
	}
	return true, nil
}

func checkSniffedRule(l *limiter.Limiter, metadata adapter.InboundContext) error {
	if target, rejected := l.CheckDestinationRule(metadata.Network, metadata.Destination.String(), metadata.Domain); rejected {
		return policyBlock{target}
	}
	if hit, ok := l.ProtocolHit(metadata.Protocol); ok {
		return policyBlock{hit}
	}
	return nil
}

type auditStream struct{ server.HyStream }

func (auditStream) LocalAddr() net.Addr  { return nil }
func (auditStream) RemoteAddr() net.Addr { return nil }

// Each request has its own identity and sniffed name. Parallel requests to
// the same destination must never share attribution.
type requestVisit struct{ tag, user, source, domain, address string }

func scopeRequest(id string, peer net.Addr, hook server.RequestHook, ob server.Outbound) (server.RequestHook, server.Outbound) {
	h := *hook.(*auditRequestHook)
	o := *ob.(*auditOutbound)
	visit := &requestVisit{tag: h.tag, user: id, source: extractIPFromAddr(peer)}
	h.visit = visit
	o.visit = visit
	return &h, &o
}

type policyBlock struct{ rule limiter.RuleHit }

func (e policyBlock) Error() string { return "blocked by panel rule " + e.rule.Label }
func (v *requestVisit) record(address, domain string, err error) {
	if v == nil {
		return
	}
	var hit limiter.RuleHit
	if err != nil {
		var block policyBlock
		if !errors.As(err, &block) {
			return
		}
		hit = block.rule
	}
	if domain == "" && address == v.address {
		domain = v.domain
	}
	if l, e := limiter.GetLimiter(v.tag); e == nil {
		l.RecordVisit(v.tag, v.user, v.source, address, domain, hit)
	}
}
