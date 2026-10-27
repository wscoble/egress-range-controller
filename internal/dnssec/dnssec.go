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

// Package dnssec resolves hostnames through validating recursive resolvers and
// fails closed unless the response carries the AD (Authenticated Data) flag.
package dnssec

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ErrNotAuthenticated means a resolver answered without AD set.
var ErrNotAuthenticated = errors.New("DNSSEC: AD flag not set")

// Resolver resolves names. Implemented by Validating and by fakes in tests.
type Resolver interface {
	// Resolve returns sorted unique addresses for host in the given families.
	Resolve(ctx context.Context, host string, families []string) ([]string, error)
}

// Validating queries resolvers in order with the DO bit set.
// A resolver entry is "ip:port" (UDP, TCP fallback on truncation) or
// "tls://ip:853#servername" (DNS over TLS).
type Validating struct {
	Resolvers []string
	RequireAD bool
	Timeout   time.Duration
}

// Resolve implements Resolver.
func (v *Validating) Resolve(ctx context.Context, host string, families []string) ([]string, error) {
	if len(v.Resolvers) == 0 {
		return nil, errors.New("no resolvers configured")
	}
	var qtypes []uint16
	for _, f := range families {
		switch f {
		case "IPv4":
			qtypes = append(qtypes, dns.TypeA)
		case "IPv6":
			qtypes = append(qtypes, dns.TypeAAAA)
		}
	}
	if len(qtypes) == 0 {
		qtypes = []uint16{dns.TypeA}
	}
	var errs []string
	for _, r := range v.Resolvers {
		addrs, err := v.resolveWith(ctx, r, host, qtypes)
		if err == nil {
			return addrs, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", r, err))
		if errors.Is(err, ErrNotAuthenticated) {
			// keep trying other resolvers, but the overall result stays fail-closed
			continue
		}
	}
	return nil, fmt.Errorf("resolve %s failed on all resolvers: %s", host, strings.Join(errs, "; "))
}

func (v *Validating) resolveWith(ctx context.Context, resolver, host string, qtypes []uint16) ([]string, error) {
	timeout := v.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	netw := "udp"
	addr := resolver
	var tlsConf *tls.Config
	if strings.HasPrefix(resolver, "tls://") {
		netw = "tcp-tls"
		addr = strings.TrimPrefix(resolver, "tls://")
		sn := ""
		if i := strings.Index(addr, "#"); i >= 0 {
			sn = addr[i+1:]
			addr = addr[:i]
		}
		if sn == "" {
			sn, _, _ = net.SplitHostPort(addr)
		}
		tlsConf = &tls.Config{ServerName: sn, MinVersion: tls.VersionTLS12}
	}
	set := map[string]bool{}
	for _, qt := range qtypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qt)
		m.RecursionDesired = true
		m.AuthenticatedData = true
		m.SetEdns0(1232, true) // DO bit
		c := &dns.Client{Net: netw, Timeout: timeout, TLSConfig: tlsConf}
		resp, _, err := c.ExchangeContext(ctx, m, addr)
		if err == nil && resp != nil && resp.Truncated && netw == "udp" {
			c.Net = "tcp"
			resp, _, err = c.ExchangeContext(ctx, m, addr)
		}
		if err != nil {
			return nil, err
		}
		if resp.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
		}
		if v.RequireAD && !resp.AuthenticatedData {
			return nil, ErrNotAuthenticated
		}
		for _, rr := range resp.Answer {
			switch a := rr.(type) {
			case *dns.A:
				set[a.A.String()] = true
			case *dns.AAAA:
				set[a.AAAA.String()] = true
			}
		}
	}
	if len(set) == 0 {
		return nil, errors.New("no addresses")
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

// Static is a fake resolver for tests and dry runs.
type Static struct {
	Answers map[string][]string
	Err     error
}

// Resolve implements Resolver.
func (s *Static) Resolve(_ context.Context, host string, _ []string) ([]string, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	a, ok := s.Answers[host]
	if !ok {
		return nil, fmt.Errorf("no answer for %s", host)
	}
	return a, nil
}
