package hy2

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/InazumaV/V2bX/limiter"
	"github.com/apernet/hysteria/extras/v2/outbounds"
)

// Resolvers fill AddrEx.ResolveInfo before calling the next stage.
type resolveSink struct{ outbounds.PluggableOutbound }

func (resolveSink) CheckUDP(*outbounds.AddrEx) error { return nil }

type checkedEgress struct {
	outbounds.PluggableOutbound
	tag      string
	resolver outbounds.PluggableOutbound
}

func (e *checkedEgress) check(a *outbounds.AddrEx) error {
	l, err := limiter.GetLimiter(e.tag)
	if err != nil {
		return err
	}
	if !l.HasIPRules() {
		return nil
	}
	if ip, err := netip.ParseAddr(a.Host); err == nil {
		if hit, ok := l.IPHit(ip); ok {
			return policyBlock{hit}
		}
		return nil
	}
	if a.ResolveInfo == nil {
		if err := e.resolver.CheckUDP(a); err != nil {
			return err
		}
	}
	info := a.ResolveInfo
	if info == nil || info.IPv4 == nil && info.IPv6 == nil {
		return fmt.Errorf("no audited address for %s", a.Host)
	}
	var first net.IP
	for _, raw := range []net.IP{info.IPv4, info.IPv6} {
		if ip, ok := netip.AddrFromSlice(raw); ok {
			if hit, ok := l.IPHit(ip); ok {
				return policyBlock{hit}
			}
			if first == nil {
				first = raw
			}
		}
	}
	if first == nil {
		return fmt.Errorf("invalid resolved address for %s", a.Host)
	}
	// Direct honors ResolveInfo (including address-family preference).
	// SOCKS and HTTP outbounds may use Host, so pin it as well.
	a.Host = first.String()
	return nil
}

func (e *checkedEgress) TCP(a *outbounds.AddrEx) (net.Conn, error) {
	if err := e.check(a); err != nil {
		return nil, err
	}
	return e.PluggableOutbound.TCP(a)
}

func (e *checkedEgress) UDP(a *outbounds.AddrEx) (outbounds.UDPConn, error) {
	if err := e.check(a); err != nil {
		return nil, err
	}
	c, err := e.PluggableOutbound.UDP(a)
	if err != nil {
		return nil, err
	}
	return &checkedPacketEgress{c, e}, nil
}

func (e *checkedEgress) CheckUDP(a *outbounds.AddrEx) error {
	if err := e.check(a); err != nil {
		return err
	}
	return e.PluggableOutbound.CheckUDP(a)
}

type checkedPacketEgress struct {
	outbounds.UDPConn
	egress *checkedEgress
}

func (c *checkedPacketEgress) WriteTo(b []byte, a *outbounds.AddrEx) (int, error) {
	if err := c.egress.check(a); err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, a)
}
