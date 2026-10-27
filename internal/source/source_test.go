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

package source

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Fixtures in testdata/ are verbatim RIPEstat responses captured 2026-10-27.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ripeServer(t *testing.T, invalidPrefix string, fail5xx *int32) *httptest.Server {
	announced := fixture(t, "announced-prefixes-AS62371.json")
	valid := string(fixture(t, "rpki-valid-185.70.42.0_24.json"))
	unknown := string(fixture(t, "rpki-unknown-203.0.113.0_24.json"))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail5xx != nil && atomic.AddInt32(fail5xx, -1) >= 0 {
			w.WriteHeader(503)
			return
		}
		if r.URL.Query().Get("sourceapp") == "" {
			t.Errorf("missing sourceapp")
		}
		switch r.URL.Path {
		case "/data/announced-prefixes/data.json":
			w.Write(announced)
		case "/data/rpki-validation/data.json":
			p := r.URL.Query().Get("prefix")
			if p == invalidPrefix {
				w.Write([]byte(strings.ReplaceAll(unknown, "203.0.113.0/24", p)))
				return
			}
			w.Write([]byte(strings.ReplaceAll(valid, "185.70.42.0/24", p)))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestRIPEstatParsesRealShapes(t *testing.T) {
	srv := ripeServer(t, "194.0.147.0/24", nil)
	defer srv.Close()
	f := &RIPEstat{ASN: 62371, BaseURL: srv.URL, SourceApp: "test", HTTP: srv.Client(), Retries: 1, Backoff: time.Millisecond}
	res, err := f.Fetch(context.Background(), []string{"IPv4"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.RPKIVerified {
		t.Fatal("RPKIVerified false")
	}
	for _, p := range res.Prefixes {
		if strings.Contains(p, ":") {
			t.Fatalf("IPv6 leaked: %s", p)
		}
		if p == "194.0.147.0/24" {
			t.Fatal("RPKI-unknown prefix accepted")
		}
	}
	found := false
	for _, p := range res.Prefixes {
		if p == "185.70.42.0/24" {
			found = true
		}
	}
	if !found || len(res.Rejected) != 1 {
		t.Fatalf("prefixes=%v rejected=%v", res.Prefixes, res.Rejected)
	}
}

func TestRIPEstatRetriesThenSucceeds(t *testing.T) {
	n := int32(2)
	srv := ripeServer(t, "", &n)
	defer srv.Close()
	f := &RIPEstat{ASN: 62371, BaseURL: srv.URL, SourceApp: "test", HTTP: srv.Client(), Retries: 3, Backoff: time.Millisecond}
	if _, err := f.Fetch(context.Background(), []string{"IPv4"}); err != nil {
		t.Fatal(err)
	}
}

func TestRIPEstatUnreachable(t *testing.T) {
	n := int32(1 << 20)
	srv := ripeServer(t, "", &n)
	defer srv.Close()
	f := &RIPEstat{ASN: 62371, BaseURL: srv.URL, SourceApp: "test", HTTP: srv.Client(), Retries: 2, Backoff: time.Millisecond}
	_, err := f.Fetch(context.Background(), []string{"IPv4"})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want ErrUnreachable, got %v", err)
	}
}

func TestRIPEstatGarbageIsInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"prefixes":[]}}`))
	}))
	defer srv.Close()
	f := &RIPEstat{ASN: 62371, BaseURL: srv.URL, SourceApp: "t", HTTP: srv.Client(), Retries: 0}
	if _, err := f.Fetch(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`<html>`)) }))
	defer srv2.Close()
	f.BaseURL = srv2.URL
	if _, err := f.Fetch(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestURLSource(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# provider list\n192.0.2.0/24\n198.51.100.7 # single host\n2001:db8::/32\n"))
	}))
	defer srv.Close()
	f := &URL{URL: srv.URL, HTTP: srv.Client(), Retries: 0}
	res, err := f.Fetch(context.Background(), []string{"IPv4"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Prefixes, ",") != "192.0.2.0/24,198.51.100.7/32" || res.RPKIVerified {
		t.Fatalf("got %+v", res)
	}
}

func TestStaticAndNew(t *testing.T) {
	s := &Static{CIDRs: []string{"192.0.2.0/24"}}
	if r, err := s.Fetch(context.Background(), nil); err != nil || len(r.Prefixes) != 1 {
		t.Fatal(r, err)
	}
	if _, err := (&Static{CIDRs: []string{"bad"}}).Fetch(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad static accepted")
	}
}
