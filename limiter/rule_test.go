package limiter

import (
	"fmt"
	"sync"
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
)

func TestAuditRules(t *testing.T) {
	l := &Limiter{}
	for _, rule := range []string{"example.com", "*.example.com"} {
		if err := l.UpdateRule(&panel.Rules{Regexp: []string{rule}}); err != nil {
			t.Fatal(err)
		}
		for _, domain := range []string{"example.com", "a.example.com", "A.EXAMPLE.COM."} {
			if !l.CheckDomainRule(domain) {
				t.Fatalf("%s did not match %s", rule, domain)
			}
		}
		for _, domain := range []string{"notexample.com", "exampleXcom", "example.com.evil.test"} {
			if l.CheckDomainRule(domain) {
				t.Fatalf("%s unexpectedly matched %s", rule, domain)
			}
		}
	}
	if err := l.UpdateRule(&panel.Rules{Regexp: []string{"regexp:example.com"}, Protocol: []string{"bittorrent"}}); err != nil {
		t.Fatal(err)
	}
	if !l.CheckDomainRule("exampleXcom") || !l.CheckProtocolRule("bittorrent") {
		t.Fatal("explicit regex or protocol semantics lost")
	}
	for _, bad := range []string{"[", "regexp:(?=example)", "regexp:"} {
		if err := l.UpdateRule(&panel.Rules{Regexp: []string{bad}}); err == nil {
			t.Fatalf("invalid rule %q accepted", bad)
		}
		if !l.CheckDomainRule("exampleXcom") || !l.CheckProtocolRule("bittorrent") {
			t.Fatal("invalid update replaced the previous working rules")
		}
	}
}

func TestAuditRulesConcurrentRefresh(t *testing.T) {
	l := &Limiter{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.CheckDomainRule("a.example.com")
				l.CheckProtocolRule("bittorrent")
				l.HasRules()
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if err := l.UpdateRule(&panel.Rules{Regexp: []string{"example.com"}, Protocol: []string{"bittorrent"}}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestXrayRAuditDestinationCompatibility(t *testing.T) {
	l := &Limiter{}
	for _, value := range []string{`^tcp:example\.com:25$`, `regexp:^tcp:example\.com:25$`} {
		if err := l.UpdateRule(&panel.Rules{Regexp: []string{value}}); err != nil {
			t.Fatal(err)
		}
		if _, blocked := l.CheckDestinationRule("tcp", "192.0.2.1:25", "example.com"); !blocked {
			t.Fatalf("XrayR-style rule %q did not match sniffed full destination", value)
		}
		if _, blocked := l.CheckDestinationRule("udp", "192.0.2.1:25", "example.com"); blocked {
			t.Fatal("TCP-only regex unexpectedly blocked UDP")
		}
	}
}

func TestIndexedAuditIPsAndSniffRequirements(t *testing.T) {
	l := &Limiter{}
	if err := l.UpdateRule(&panel.Rules{Regexp: []string{"192.0.2.1", "2001:db8::1"}}); err != nil {
		t.Fatal(err)
	}
	if !l.HasRules() || l.NeedsSniff() {
		t.Fatal("IP-only rules should be enforced without payload sniffing")
	}
	for _, host := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:0db8:0:0:0:0:0:1"} {
		if !l.CheckDomainRule(host) {
			t.Fatalf("canonical IP lookup missed %s", host)
		}
	}
	for _, host := range []string{"192.0.2.10", "2001:db8::10", "a.192.0.2.1"} {
		if l.CheckDomainRule(host) {
			t.Fatalf("IP rule incorrectly matched %s", host)
		}
	}
	for _, rules := range []panel.Rules{
		{Regexp: []string{"example.com"}},
		{Regexp: []string{"regexp:^example"}},
		{Protocol: []string{"bittorrent"}},
	} {
		if err := l.UpdateRule(&rules); err != nil {
			t.Fatal(err)
		}
		if !l.NeedsSniff() {
			t.Fatal("domain/regex/protocol rules lost sniffing")
		}
	}
}

func TestDestinationCacheRefresh(t *testing.T) {
	l := &Limiter{}
	var cache DestinationCache
	const address = "192.0.2.1:443"
	if _, rejected := cache.Check(l, "udp", address, ""); rejected {
		t.Fatal("empty rules unexpectedly rejected the target")
	}
	if err := l.UpdateRule(&panel.Rules{Regexp: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, rejected := cache.Check(l, "udp", address, ""); !rejected {
			t.Fatal("cached allow decision survived a rule update")
		}
	}
	if _, rejected := cache.Check(l, "udp", "192.0.2.2:443", ""); rejected {
		t.Fatal("cached rejection incorrectly applied to another target")
	}
	if err := l.UpdateRule(&panel.Rules{}); err != nil {
		t.Fatal(err)
	}
	if _, rejected := cache.Check(l, "udp", address, ""); rejected {
		t.Fatal("cached rejection survived rule removal")
	}
}

func TestDestinationCacheConcurrentRefresh(t *testing.T) {
	l := &Limiter{}
	var cache DestinationCache
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 100; j++ {
				cache.Check(l, "udp", "192.0.2.1:443", "")
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if err := l.UpdateRule(&panel.Rules{Regexp: []string{"192.0.2.1"}}); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
	if _, rejected := cache.Check(l, "udp", "192.0.2.1:443", ""); !rejected {
		t.Fatal("last published rules were not enforced")
	}
}

func BenchmarkAuditMatching(b *testing.B) {
	for _, count := range []int{1, 1000, 10000} {
		rules := make([]string, count)
		for i := range rules {
			rules[i] = fmt.Sprintf("site%04d.com", i)
		}
		l := &Limiter{}
		if err := l.UpdateRule(&panel.Rules{Regexp: rules}); err != nil {
			b.Fatal(err)
		}
		for _, tc := range []struct{ name, network, address, domain string }{
			{"TCP_domain", "tcp", "www.allowed.example.com:443", "www.allowed.example.com"},
			{"TCP_IP_sniff", "tcp", "203.0.113.1:443", "www.allowed.example.com"},
			{"UDP", "udp", "203.0.113.1:443", ""},
		} {
			b.Run(fmt.Sprintf("%d_domains/%s", count, tc.name), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, rejected := l.CheckDestinationRule(tc.network, tc.address, tc.domain); rejected {
						b.Fatal("allowed target was rejected")
					}
				}
			})
		}
	}
	rules := make([]string, 1000)
	for i := range rules {
		rules[i] = fmt.Sprintf(`regexp:(?i)(^|\.)site%04d\.com$`, i)
	}
	l := &Limiter{}
	if err := l.UpdateRule(&panel.Rules{Regexp: rules}); err != nil {
		b.Fatal(err)
	}
	b.Run("1000_regex/UDP_uncached", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, rejected := l.CheckDestinationRule("udp", "203.0.113.1:443", ""); rejected {
				b.Fatal("allowed target was rejected")
			}
		}
	})
	b.Run("1000_regex/UDP_cached", func(b *testing.B) {
		var cache DestinationCache
		cache.Check(l, "udp", "203.0.113.1:443", "")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, rejected := cache.Check(l, "udp", "203.0.113.1:443", ""); rejected {
				b.Fatal("allowed target was rejected")
			}
		}
	})
}

// Renaming entries or moving the same match to another group must not relabel
// an event already produced, including cached verdicts for an active UDP flow.
func TestAuditGroupAttribution(t *testing.T) {
	l := &Limiter{}
	var cache DestinationCache
	rules := panel.Rules{Regexp: []string{"*.example.org", "127.0.0.1", "regexp:^special$"}, Protocol: []string{"bittorrent"},
		RouteIDs: map[string]int{"*.example.org": 2, "127.0.0.1": 3, "regexp:^special$": 4, "protocol:bittorrent": 5}}
	if err := l.UpdateRule(&rules); err != nil {
		t.Fatal(err)
	}
	original, _ := cache.Check(l, "udp", "sub.example.org:443", "")
	if original != (RuleHit{"*.example.org", 2}) {
		t.Fatal(original)
	}
	for target, want := range map[string]int{"127.0.0.1:80": 3, "special:80": 4} {
		if hit, ok := l.CheckDestinationRule("tcp", target, ""); !ok || hit.RouteID != want {
			t.Fatal(target, hit)
		}
	}
	if hit, ok := l.ProtocolHit("bittorrent"); !ok || hit.RouteID != 5 {
		t.Fatal(hit)
	}
	rules.RouteIDs["*.example.org"] = 9
	if err := l.UpdateRule(&rules); err != nil {
		t.Fatal(err)
	}
	if hit, _ := cache.Check(l, "udp", "sub.example.org:443", ""); hit.RouteID != 9 || original.RouteID != 2 {
		t.Fatal(original, hit)
	}
}
