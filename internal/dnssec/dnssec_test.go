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

package dnssec

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startServer(t *testing.T, ad bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = ad
		if opt := r.IsEdns0(); opt == nil || !opt.Do() {
			m.Rcode = dns.RcodeRefused // the client must set DO
		} else if r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 185.70.42.41")
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestADRequired(t *testing.T) {
	good := startServer(t, true)
	bad := startServer(t, false)
	v := &Validating{Resolvers: []string{good}, RequireAD: true, Timeout: time.Second}
	ips, err := v.Resolve(context.Background(), "mail-api.proton.me", []string{"IPv4"})
	if err != nil || len(ips) != 1 || ips[0] != "185.70.42.41" {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
	v = &Validating{Resolvers: []string{bad}, RequireAD: true, Timeout: time.Second}
	if _, err := v.Resolve(context.Background(), "mail-api.proton.me", []string{"IPv4"}); err == nil {
		t.Fatal("accepted answer without AD (must fail closed)")
	}
	// falls through to a validating resolver
	v = &Validating{Resolvers: []string{bad, good}, RequireAD: true, Timeout: time.Second}
	if _, err := v.Resolve(context.Background(), "mail-api.proton.me", []string{"IPv4"}); err != nil {
		t.Fatal(err)
	}
	v = &Validating{Resolvers: []string{bad}, RequireAD: false, Timeout: time.Second}
	if _, err := v.Resolve(context.Background(), "mail-api.proton.me", []string{"IPv4"}); err != nil {
		t.Fatal(err)
	}
}

func TestStaticResolver(t *testing.T) {
	s := &Static{Answers: map[string][]string{"a": {"1.2.3.4"}}}
	if _, err := s.Resolve(context.Background(), "b", nil); err == nil {
		t.Fatal("expected error")
	}
	s.Err = errors.New("x")
	if _, err := s.Resolve(context.Background(), "a", nil); err == nil {
		t.Fatal("expected error")
	}
}
