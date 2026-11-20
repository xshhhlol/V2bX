// Package auditpacket identifies UDP metadata before forwarding.
package auditpacket

import (
	"bytes"
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	M "github.com/sagernet/sing/common/metadata"
)

// Inspector belongs to one sequential UDP writer. Keep at most eight QUIC
// Initial packets' crypto fragments for one destination and connection ID.
type Inspector struct {
	destination  M.Socksaddr
	connectionID []byte
	fragments    any
	packets      int
}

func (s *Inspector) Inspect(destination M.Socksaddr, payload []byte, protocols bool) (domain, protocol string) {
	ctx := context.Background()
	var m adapter.InboundContext
	if len(payload) > 6 && payload[0]&0xc0 == 0xc0 {
		idLength := int(payload[5])
		if idLength > 0 && idLength <= 20 && len(payload) >= 6+idLength {
			id := payload[6 : 6+idLength]
			if s.destination != destination || !bytes.Equal(s.connectionID, id) || s.packets >= 8 {
				s.fragments = nil
				s.packets = 0
				s.destination = destination
				s.connectionID = append(s.connectionID[:0], id...)
			}
			m.SniffContext = s.fragments
			_ = sniff.QUICClientHello(ctx, &m, payload)
			s.fragments = m.SniffContext
			if s.fragments == nil {
				s.packets = 0
			} else {
				s.packets++
			}
			if m.Protocol != "" {
				return m.Domain, m.Protocol
			}
		}
	}
	// Domain lists only need QUIC SNI here. Avoid parsing every unrelated
	// datagram as DNS when the policy contains only domains and IP addresses.
	if protocols {
		for _, probe := range []sniff.PacketSniffer{sniff.UDPTracker, sniff.STUNMessage, sniff.DTLSRecord, sniff.UTP, sniff.NTP, sniff.DomainNameQuery} {
			if probe(ctx, &m, payload) == nil && m.Protocol != "" {
				return m.Domain, m.Protocol
			}
		}
	}
	return "", ""
}
