package node

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

func (c *Controller) refreshVisits(ctx context.Context) {
	rules, etag, err := c.apiClient.VisitRules(ctx, c.visitEtag)
	if err == nil && rules != nil {
		err = c.visits.Update(rules)
		if err == nil {
			c.visitEtag = etag
		}
	}
	if err != nil && ctx.Err() == nil {
		log.WithField("node", c.apiClient.NodeId).WithError(err).Warn("Refresh visit rules failed")
	}
}

func (c *Controller) flushVisits(ctx context.Context) {
	if n := c.visits.Dropped(); n > 0 {
		log.WithField("dropped", n).Warn("Visit queue full")
	}
	for i := 0; i < 9; i++ {
		batch := c.visits.Batch()
		if len(batch) == 0 {
			return
		}
		if err := c.apiClient.ReportVisits(ctx, batch); err != nil {
			if ctx.Err() == nil {
				log.WithError(err).Warn("Visit batch retained for retry")
			}
			return
		}
		c.visits.Confirm(len(batch))
	}
}

func (c *Controller) startVisits(interval time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	c.stopVisits = cancel
	c.visitDone = make(chan struct{})
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		defer close(c.visitDone)
		refresh := time.NewTicker(interval)
		defer refresh.Stop()
		flush := time.NewTicker(5 * time.Second)
		defer flush.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-refresh.C:
				c.refreshVisits(ctx)
			case <-flush.C:
				c.flushVisits(ctx)
			}
		}
	}()
}
