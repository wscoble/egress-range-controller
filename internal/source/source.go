/*
Copyright 2026 Greybeard Holdings LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package source fetches candidate prefixes from a provider.
package source

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
	"github.com/wscoble/egress-range-controller/internal/ranges"
)

// ErrUnreachable marks transport failures (timeouts, 5xx, DNS) after retries.
var ErrUnreachable = errors.New("source unreachable")

// ErrInvalid marks responses that parsed badly or were empty/implausible.
var ErrInvalid = errors.New("source returned invalid data")

// Result is a successful fetch.
type Result struct {
	// Prefixes are the accepted (for RIPEstat: RPKI-valid for the ASN) prefixes, normalised.
	Prefixes []string
	// Rejected are prefixes seen but not accepted (e.g. RPKI not valid), with reason.
	Rejected []string
	// RPKIVerified is true when every accepted prefix was RPKI-validated.
	RPKIVerified bool
	// Source is a short human description.
	Source string
}

// Fetcher fetches a Result.
type Fetcher interface {
	Fetch(ctx context.Context, families []string) (Result, error)
}

// New builds a Fetcher from the spec.
func New(s v1.Source, client *http.Client) (Fetcher, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	switch s.Type {
	case "", v1.SourceRIPEstatRPKI:
		if s.RIPEstat == nil || s.RIPEstat.ASN == 0 {
			return nil, fmt.Errorf("source.ripestat.asn is required")
		}
		base := s.RIPEstat.BaseURL
		if base == "" {
			base = "https://stat.ripe.net"
		}
		app := s.RIPEstat.SourceApp
		if app == "" {
			app = "egress-range-controller"
		}
		return &RIPEstat{ASN: s.RIPEstat.ASN, BaseURL: strings.TrimRight(base, "/"), SourceApp: app, HTTP: client, Retries: 3, Backoff: time.Second}, nil
	case v1.SourceStatic:
		if s.Static == nil {
			return nil, fmt.Errorf("source.static is required")
		}
		return &Static{CIDRs: s.Static.CIDRs}, nil
	case v1.SourceURL:
		if s.URL == nil || !strings.HasPrefix(s.URL.URL, "https://") {
			return nil, fmt.Errorf("source.url.url must be https")
		}
		return &URL{URL: s.URL.URL, HTTP: client, Retries: 3, Backoff: time.Second}, nil
	}
	return nil, fmt.Errorf("unknown source type %q", s.Type)
}

// Static returns a fixed list.
type Static struct{ CIDRs []string }

// Fetch implements Fetcher.
func (s *Static) Fetch(_ context.Context, families []string) (Result, error) {
	n, err := ranges.Normalize(s.CIDRs)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	n = ranges.FilterFamilies(n, families)
	if len(n) == 0 {
		return Result{}, fmt.Errorf("%w: static list empty", ErrInvalid)
	}
	return Result{Prefixes: n, Source: "static"}, nil
}

// getWithRetry performs GET with bounded exponential backoff on transport
// errors, 429 and 5xx. Other statuses are ErrInvalid.
func getWithRetry(ctx context.Context, c *http.Client, u string, retries int, backoff time.Duration) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w: %v", ErrUnreachable, ctx.Err())
			case <-time.After(backoff << (attempt - 1)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "egress-range-controller/0.1 (+https://github.com/wscoble/egress-range-controller)")
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%w: HTTP %d from %s", ErrInvalid, resp.StatusCode, u)
		}
		return body, nil
	}
	return nil, fmt.Errorf("%w: %s: %v", ErrUnreachable, u, lastErr)
}

// URL fetches a newline-separated CIDR list.
type URL struct {
	URL     string
	HTTP    *http.Client
	Retries int
	Backoff time.Duration
}

// Fetch implements Fetcher.
func (s *URL) Fetch(ctx context.Context, families []string) (Result, error) {
	body, err := getWithRetry(ctx, s.HTTP, s.URL, s.Retries, s.Backoff)
	if err != nil {
		return Result{}, err
	}
	var raw []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		line := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		if line != "" {
			raw = append(raw, line)
		}
	}
	n, err := ranges.Normalize(raw)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	n = ranges.FilterFamilies(n, families)
	if len(n) == 0 {
		return Result{}, fmt.Errorf("%w: list empty", ErrInvalid)
	}
	return Result{Prefixes: n, Source: "url " + s.URL}, nil
}

// RIPEstat implements the ripestat-rpki source.
type RIPEstat struct {
	ASN         int64
	BaseURL     string
	SourceApp   string
	HTTP        *http.Client
	Retries     int
	Backoff     time.Duration
	Concurrency int
}

type announcedResp struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

type rpkiResp struct {
	Status string `json:"status"`
	Data   struct {
		Prefix         string `json:"prefix"`
		Status         string `json:"status"`
		Validator      string `json:"validator"`
		ValidatingROAs []struct {
			Origin    string `json:"origin"`
			Prefix    string `json:"prefix"`
			Validity  string `json:"validity"`
			MaxLength int    `json:"max_length"`
		} `json:"validating_roas"`
	} `json:"data"`
}

func (r *RIPEstat) url(call string, q url.Values) string {
	q.Set("sourceapp", r.SourceApp)
	return r.BaseURL + "/data/" + call + "/data.json?" + q.Encode()
}

// Fetch lists announced prefixes for the ASN and keeps those whose RPKI
// validation status is "valid" with a validating ROA for this origin.
func (r *RIPEstat) Fetch(ctx context.Context, families []string) (Result, error) {
	asn := "AS" + strconv.FormatInt(r.ASN, 10)
	body, err := getWithRetry(ctx, r.HTTP, r.url("announced-prefixes", url.Values{"resource": {asn}}), r.Retries, r.Backoff)
	if err != nil {
		return Result{}, err
	}
	var ar announcedResp
	if err := json.Unmarshal(body, &ar); err != nil {
		return Result{}, fmt.Errorf("%w: announced-prefixes: %v", ErrInvalid, err)
	}
	if ar.Status != "ok" {
		return Result{}, fmt.Errorf("%w: announced-prefixes status %q", ErrInvalid, ar.Status)
	}
	var raw []string
	for _, p := range ar.Data.Prefixes {
		raw = append(raw, p.Prefix)
	}
	announced, err := ranges.Normalize(raw)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	announced = ranges.FilterFamilies(announced, families)
	if len(announced) == 0 {
		return Result{}, fmt.Errorf("%w: no announced prefixes for %s", ErrInvalid, asn)
	}

	conc := r.Concurrency
	if conc <= 0 {
		conc = 4
	}
	type out struct {
		prefix string
		valid  bool
		reason string
		err    error
	}
	results := make([]out, len(announced))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	origin := strconv.FormatInt(r.ASN, 10)
	for i, p := range announced {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			b, err := getWithRetry(ctx, r.HTTP, r.url("rpki-validation", url.Values{"resource": {asn}, "prefix": {p}}), r.Retries, r.Backoff)
			if err != nil {
				results[i] = out{prefix: p, err: err}
				return
			}
			var rr rpkiResp
			if err := json.Unmarshal(b, &rr); err != nil || rr.Status != "ok" {
				results[i] = out{prefix: p, err: fmt.Errorf("%w: rpki-validation for %s unparseable", ErrInvalid, p)}
				return
			}
			roaOK := false
			for _, roa := range rr.Data.ValidatingROAs {
				if strings.TrimPrefix(roa.Origin, "AS") == origin && roa.Validity == "valid" {
					roaOK = true
				}
			}
			if rr.Data.Status == "valid" && roaOK {
				results[i] = out{prefix: p, valid: true}
			} else {
				results[i] = out{prefix: p, reason: rr.Data.Status}
			}
		}(i, p)
	}
	wg.Wait()

	res := Result{RPKIVerified: true, Source: fmt.Sprintf("RIPEstat announced-prefixes+rpki-validation %s", asn)}
	for _, o := range results {
		if o.err != nil {
			// Fail the whole fetch rather than act on a partial view.
			return Result{}, o.err
		}
		if o.valid {
			res.Prefixes = append(res.Prefixes, o.prefix)
		} else {
			res.Rejected = append(res.Rejected, o.prefix+" ("+o.reason+")")
		}
	}
	if len(res.Prefixes) == 0 {
		return Result{}, fmt.Errorf("%w: no RPKI-valid prefixes for %s", ErrInvalid, asn)
	}
	res.Prefixes = ranges.MustNormalize(res.Prefixes)
	return res, nil
}
