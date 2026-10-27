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

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
	"github.com/wscoble/egress-range-controller/internal/dnssec"
	"github.com/wscoble/egress-range-controller/internal/engine"
	"github.com/wscoble/egress-range-controller/internal/source"
)

// Observer performs one fetch cycle. Fields are injectable for tests.
type Observer struct {
	HTTP        *http.Client
	NewFetcher  func(v1.Source, *http.Client) (source.Fetcher, error)
	NewResolver func(v1.DNSSECConfig) dnssec.Resolver
}

// DefaultResolver builds the validating resolver from spec (defaults: 1.1.1.1 and 9.9.9.9 over DoT, AD required).
func DefaultResolver(c v1.DNSSECConfig) dnssec.Resolver {
	rs := c.Resolvers
	if len(rs) == 0 {
		rs = []string{"tls://1.1.1.1:853#cloudflare-dns.com", "tls://9.9.9.9:853#dns.quad9.net"}
	}
	t := 5 * time.Second
	if c.Timeout != nil && c.Timeout.Duration > 0 {
		t = c.Timeout.Duration
	}
	return &dnssec.Validating{Resolvers: rs, RequireAD: c.RequireAD == nil || *c.RequireAD, Timeout: t}
}

// Observe fetches the source and resolves endpoints.
func (o *Observer) Observe(ctx context.Context, spec v1.EgressRangesSpec, cfg engine.Config) *engine.Observation {
	nf := o.NewFetcher
	if nf == nil {
		nf = source.New
	}
	nr := o.NewResolver
	if nr == nil {
		nr = DefaultResolver
	}
	obs := &engine.Observation{}
	f, err := nf(spec.Source, o.HTTP)
	if err != nil {
		obs.FetchErr = fmt.Errorf("%w: %v", source.ErrInvalid, err)
		return obs
	}
	fctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	res, err := f.Fetch(fctx, cfg.Families)
	obs.Source = res
	if err != nil {
		if !errors.Is(err, source.ErrUnreachable) && !errors.Is(err, source.ErrInvalid) {
			err = fmt.Errorf("%w: %v", source.ErrUnreachable, err)
		}
		obs.FetchErr = err
		return obs
	}
	if len(cfg.Endpoints) == 0 {
		return obs
	}
	r := nr(spec.DNSSEC)
	obs.Resolved = map[string][]string{}
	var errs []string
	for _, h := range cfg.Endpoints {
		ips, err := r.Resolve(ctx, h, cfg.Families)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		obs.Resolved[h] = ips
	}
	if len(errs) > 0 {
		// Fail closed: a partial view never drives the candidate.
		obs.DNSErr = errors.New(strings.Join(errs, "; "))
		obs.Resolved = nil
	}
	return obs
}
