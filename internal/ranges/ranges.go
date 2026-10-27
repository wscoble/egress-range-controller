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

// Package ranges holds pure helpers for CIDR sets: normalisation, digests,
// diffs and containment.
package ranges

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Normalize parses, masks, de-duplicates and sorts CIDRs. Bare addresses
// become host prefixes (/32 or /128).
func Normalize(in []string) ([]string, error) {
	seen := map[string]bool{}
	var ps []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var p netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			p, err = netip.ParsePrefix(s)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(s)
			if err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		p = p.Masked()
		if !seen[p.String()] {
			seen[p.String()] = true
			ps = append(ps, p)
		}
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Addr() != ps[j].Addr() {
			return ps[i].Addr().Less(ps[j].Addr())
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out, nil
}

// MustNormalize panics on error; for tests and constants.
func MustNormalize(in []string) []string {
	out, err := Normalize(in)
	if err != nil {
		panic(err)
	}
	return out
}

// Digest is sha256 over the normalised, newline-joined set, prefixed "sha256:".
func Digest(cidrs []string) string {
	n := MustNormalize(cidrs)
	h := sha256.Sum256([]byte(strings.Join(n, "\n")))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Union returns the normalised union.
func Union(a, b []string) []string {
	return MustNormalize(append(append([]string{}, a...), b...))
}

// Diff returns entries in next but not prev (added) and in prev but not next (removed).
func Diff(prev, next []string) (added, removed []string) {
	p := toSet(prev)
	n := toSet(next)
	for k := range n {
		if !p[k] {
			added = append(added, k)
		}
	}
	for k := range p {
		if !n[k] {
			removed = append(removed, k)
		}
	}
	added = MustNormalize(added)
	removed = MustNormalize(removed)
	return
}

// ChangeFraction is (added+removed)/max(len(prev),1).
func ChangeFraction(prev, next []string) float64 {
	a, r := Diff(prev, next)
	d := len(prev)
	if d == 0 {
		d = 1
	}
	return float64(len(a)+len(r)) / float64(d)
}

// Contains reports whether ip is inside any of cidrs.
func Contains(cidrs []string, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// ContainsAll reports whether every element of sub is in set (exact match).
func ContainsAll(set, sub []string) bool {
	s := toSet(set)
	for _, x := range MustNormalize(sub) {
		if !s[x] {
			return false
		}
	}
	return true
}

// FilterFamilies keeps only prefixes of the given families ("IPv4", "IPv6").
func FilterFamilies(cidrs []string, families []string) []string {
	want4, want6 := false, false
	if len(families) == 0 {
		want4 = true
	}
	for _, f := range families {
		switch f {
		case "IPv4":
			want4 = true
		case "IPv6":
			want6 = true
		}
	}
	var out []string
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if (p.Addr().Is4() && want4) || (p.Addr().Is6() && want6) {
			out = append(out, p.Masked().String())
		}
	}
	return out
}

// Equal compares normalised sets.
func Equal(a, b []string) bool { return Digest(a) == Digest(b) }

func toSet(in []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range MustNormalize(in) {
		m[x] = true
	}
	return m
}
