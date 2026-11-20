package limiter

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/format"
)

type watchList struct {
	suffix      map[string]bool
	keywords    []string
	expressions []*regexp.Regexp
}

type VisitMonitor struct {
	list    atomic.Pointer[watchList]
	mu      sync.Mutex
	queue   []panel.Visit
	dropped atomic.Uint64
}

func (v *VisitMonitor) Update(r *panel.VisitRules) error {
	w := &watchList{suffix: make(map[string]bool)}
	for _, s := range r.Suffixes {
		s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
		if s != "" {
			w.suffix[s] = true
		}
	}
	for _, s := range r.Keywords {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			w.keywords = append(w.keywords, s)
		}
	}
	for _, s := range r.Regexes {
		e, err := regexp.Compile(s)
		if err != nil {
			return fmt.Errorf("visit rule %q: %w", s, err)
		}
		w.expressions = append(w.expressions, e)
	}
	v.list.Store(w)
	return nil
}

func (w *watchList) match(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for part := host; part != ""; {
		if w.suffix[part] {
			return part
		}
		_, tail, ok := strings.Cut(part, ".")
		if !ok {
			break
		}
		part = tail
	}
	for _, k := range w.keywords {
		if strings.Contains(host, k) {
			return "kw:" + k
		}
	}
	for _, e := range w.expressions {
		if e.MatchString(host) {
			return "re:" + e.String()
		}
	}
	return ""
}

func (l *Limiter) SetVisits(v *VisitMonitor) { l.visits.Store(v) }
func (l *Limiter) WatchesVisits() bool {
	v := l.visits.Load()
	if v == nil {
		return false
	}
	w := v.list.Load()
	return w != nil && len(w.suffix)+len(w.keywords)+len(w.expressions) > 0
}

// Record only watchlist matches and explicit policy rejections. Never transmit credentials.
func (l *Limiter) RecordVisit(tag, user, source, address, domain string, blockedBy RuleHit) {
	v := l.visits.Load()
	if v == nil {
		return
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	dest, hit, status := host, blockedBy.Label, "rejected"
	if domain != "" {
		dest = domain
	}
	if hit == "" {
		w := v.list.Load()
		if w == nil {
			return
		}
		status = "accepted"
		hit = w.match(dest)
		if hit == "" && host != dest {
			dest = host
			hit = w.match(host)
		}
		if hit == "" {
			return
		}
	}
	var uid int
	if item, ok := l.UserLimitInfo.Load(format.UserTag(tag, user)); ok {
		uid = item.(*UserLimitInfo).UID
	}
	if uid <= 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.queue) >= 8192 {
		v.dropped.Add(1)
		return
	}
	v.queue = append(v.queue, panel.Visit{BlockRouteID: blockedBy.RouteID, UID: uid, Source: source, Destination: dest, Hit: hit, Status: status, Time: time.Now().Unix()})
}

func (v *VisitMonitor) Batch() []panel.Visit {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]panel.Visit(nil), v.queue[:min(len(v.queue), 1000)]...)
}

func (v *VisitMonitor) Confirm(n int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.queue[:n])
	v.queue = v.queue[n:]
}

func (v *VisitMonitor) Dropped() uint64 { return v.dropped.Swap(0) }
