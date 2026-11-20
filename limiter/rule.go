package limiter

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/InazumaV/V2bX/api/panel"
)

type RuleHit struct {
	Label   string
	RouteID int
}

type regexRule struct {
	expression *regexp.Regexp
	hit        RuleHit
}

// Compiled sets are immutable, including the group that supplied each rule.
type auditRules struct {
	domains   map[string]RuleHit
	ips       map[netip.Addr]RuleHit
	protocols map[string]RuleHit
	regexps   []regexRule
}

func (l *Limiter) CheckDomainRule(destination string) bool {
	rules := l.rules.Load()
	if rules == nil {
		return false
	}
	destination = strings.TrimSuffix(destination, ".")
	_, literal := rules.matchLiteral(destination)
	if literal {
		return true
	}
	_, matched := rules.matchRegexp(destination)
	return matched
}

func (r *auditRules) matchLiteral(host string) (RuleHit, bool) {
	if len(r.ips) > 0 {
		if ip, err := netip.ParseAddr(host); err == nil {
			if hit, ok := r.ips[ip.Unmap()]; ok {
				return hit, true
			}
		}
	}
	if len(r.domains) > 0 {
		for h := strings.ToLower(strings.TrimSuffix(host, ".")); h != ""; {
			if hit, ok := r.domains[h]; ok {
				return hit, true
			}
			_, tail, ok := strings.Cut(h, ".")
			if !ok {
				break
			}
			h = tail
		}
	}
	return RuleHit{}, false
}

func (r *auditRules) matchRegexp(value string) (RuleHit, bool) {
	for _, rule := range r.regexps {
		if rule.expression.MatchString(value) {
			return rule.hit, true
		}
	}
	return RuleHit{}, false
}

func (l *Limiter) ProtocolHit(protocol string) (RuleHit, bool) {
	r := l.rules.Load()
	if r == nil {
		return RuleHit{}, false
	}
	hit, ok := r.protocols[protocol]
	return hit, ok
}

func (l *Limiter) CheckProtocolRule(protocol string) bool {
	_, ok := l.ProtocolHit(protocol)
	return ok
}

// Regex rules retain XrayR's full destination forms. Literal domain/IP rules
// only need the actual and sniffed host, avoiding repeated full-list scans.
func (l *Limiter) CheckDestinationRule(network, address, domain string) (RuleHit, bool) {
	return l.rules.Load().checkDestination(network, address, domain)
}

func (r *auditRules) checkDestination(network, address, domain string) (RuleHit, bool) {
	if r == nil || len(r.domains)+len(r.ips)+len(r.regexps) == 0 {
		return RuleHit{}, false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if hit, ok := r.matchLiteral(host); ok {
		return hit, true
	}
	if domain != "" && domain != host {
		if hit, ok := r.matchLiteral(domain); ok {
			return hit, true
		}
	}
	if len(r.regexps) == 0 {
		return RuleHit{}, false
	}
	candidates := [6]string{host, address}
	count := 2
	if network != "" {
		candidates[count] = network + ":" + address
		count++
	}
	if domain != "" && domain != host {
		candidates[count] = domain
		count++
		if port != "" {
			full := net.JoinHostPort(domain, port)
			candidates[count] = full
			count++
			if network != "" {
				candidates[count] = network + ":" + full
				count++
			}
		}
	}
	for i, candidate := range candidates[:count] {
		candidate = strings.TrimSuffix(candidate, ".")
		if candidate == "" {
			continue
		}
		duplicate := false
		for _, previous := range candidates[:i] {
			if candidate == strings.TrimSuffix(previous, ".") {
				duplicate = true
				break
			}
		}
		if !duplicate {
			if hit, ok := r.matchRegexp(candidate); ok {
				return hit, true
			}
		}
	}
	return RuleHit{}, false
}

func (l *Limiter) UpdateRule(rule *panel.Rules) error {
	compiled, err := compileRules(rule)
	if err != nil {
		return err
	}
	l.rules.Store(compiled)
	return nil
}

func (l *Limiter) HasRules() bool {
	r := l.rules.Load()
	return r != nil && len(r.domains)+len(r.ips)+len(r.regexps)+len(r.protocols) != 0
}

// IP-only rules are completely enforced by the outbound guard and do not need
// payload inspection or its server-first timeout.
func (l *Limiter) NeedsSniff() bool {
	r := l.rules.Load()
	return r != nil && len(r.domains)+len(r.regexps)+len(r.protocols) != 0
}

func ValidateRules(rule *panel.Rules) error {
	_, err := compileRules(rule)
	return err
}

var domainRule = regexp.MustCompile(`(?i)^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.?$`)

func compileRules(rule *panel.Rules) (*auditRules, error) {
	compiled := &auditRules{
		domains:   make(map[string]RuleHit),
		ips:       make(map[netip.Addr]RuleHit),
		protocols: make(map[string]RuleHit, len(rule.Protocol)),
	}
	for _, protocol := range rule.Protocol {
		label := "protocol:" + protocol
		compiled.protocols[protocol] = RuleHit{label, rule.RouteIDs[label]}
	}
	seenRegex := make(map[string]bool)
	for _, value := range rule.Regexp {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		expr := value
		if strings.HasPrefix(value, "regexp:") {
			expr = strings.TrimPrefix(value, "regexp:")
		} else if ip, err := netip.ParseAddr(value); err == nil {
			if _, ok := compiled.ips[ip.Unmap()]; !ok {
				compiled.ips[ip.Unmap()] = RuleHit{value, rule.RouteIDs[value]}
			}
			continue
		} else if host := strings.TrimPrefix(value, "*."); domainRule.MatchString(host) {
			key := strings.ToLower(strings.TrimSuffix(host, "."))
			if _, ok := compiled.domains[key]; !ok {
				compiled.domains[key] = RuleHit{value, rule.RouteIDs[value]}
			}
			continue
		}
		if expr == "" {
			return nil, fmt.Errorf("empty audit regular expression")
		}
		if _, duplicate := seenRegex[expr]; duplicate {
			continue
		}
		expression, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid audit rule %q: %w", value, err)
		}
		compiled.regexps = append(compiled.regexps, regexRule{expression, RuleHit{value, rule.RouteIDs[value]}})
		seenRegex[expr] = true
	}
	return compiled, nil
}

// DestinationCache belongs to one UDP association, not the global node. It only
// remembers one target, keeping memory bounded even when clients scan targets.
// A new rule snapshot always invalidates it, including previously allowed IPs.
type DestinationCache struct {
	mu                       sync.Mutex
	rules                    *auditRules
	network, address, domain string
	matched                  RuleHit
	rejected, valid          bool
}

func (c *DestinationCache) Check(l *Limiter, network, address, domain string) (RuleHit, bool) {
	rules := l.rules.Load()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.valid && c.rules == rules && c.network == network && c.address == address && c.domain == domain {
		return c.matched, c.rejected
	}
	matched, rejected := rules.checkDestination(network, address, domain)
	c.rules, c.network, c.address, c.domain = rules, network, address, domain
	c.matched, c.rejected, c.valid = matched, rejected, true
	return matched, rejected
}

func (l *Limiter) HasIPRules() bool { r := l.rules.Load(); return r != nil && len(r.ips) > 0 }

func (l *Limiter) IPHit(ip netip.Addr) (RuleHit, bool) {
	r := l.rules.Load()
	if r == nil {
		return RuleHit{}, false
	}
	hit, ok := r.ips[ip.Unmap()]
	return hit, ok
}

func (l *Limiter) HasProtocolRules() bool {
	r := l.rules.Load()
	return r != nil && len(r.protocols) != 0
}
