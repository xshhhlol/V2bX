package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

type VisitRules struct {
	Suffixes []string `json:"suffixes"`
	Keywords []string `json:"keywords"`
	Regexes  []string `json:"regexes"`
}

type Visit struct {
	BlockRouteID int    `json:"block_route_id,omitempty"`
	UID          int    `json:"uid"`
	Source       string `json:"src_ip"`
	Destination  string `json:"dest"`
	Hit          string `json:"hit"`
	Status       string `json:"status"`
	Time         int64  `json:"time"`
}

func (c *Client) VisitRules(ctx context.Context, etag string) (*VisitRules, string, error) {
	r, err := c.client.R().SetContext(ctx).SetHeader("If-None-Match", etag).Get("/api/v1/server/UniProxy/visitRule")
	if err != nil {
		return nil, etag, redactVisitError(err)
	}
	if r.StatusCode() == 304 {
		return nil, etag, nil
	}
	if r.StatusCode() != 200 {
		return nil, etag, fmt.Errorf("visitRule returned HTTP %d", r.StatusCode())
	}
	var rules VisitRules
	if err = json.Unmarshal(r.Body(), &rules); err != nil {
		return nil, etag, err
	}
	if rules.Suffixes == nil || rules.Keywords == nil || rules.Regexes == nil {
		return nil, etag, fmt.Errorf("missing observation lists")
	}
	return &rules, r.Header().Get("ETag"), nil
}

func (c *Client) ReportVisits(ctx context.Context, visits []Visit) error {
	r, err := c.client.R().SetContext(ctx).SetBody(visits).Post("/api/v1/server/UniProxy/visit")
	if err != nil {
		return redactVisitError(err)
	}
	var ack struct{ Data bool }
	if r.StatusCode() != 200 || json.Unmarshal(r.Body(), &ack) != nil || !ack.Data {
		return fmt.Errorf("visit batch unconfirmed (HTTP %d)", r.StatusCode())
	}
	return nil
}

// Resty transport errors may include the query string containing the node token.
func redactVisitError(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err
	}
	return err
}
