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

package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
	"github.com/wscoble/egress-range-controller/internal/ranges"
	"github.com/wscoble/egress-range-controller/internal/source"
)

// fakeClock is advanced explicitly by tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func baseSpec() v1.EgressRangesSpec {
	return v1.EgressRangesSpec{
		Source:    v1.Source{Type: v1.SourceRIPEstatRPKI, RIPEstat: &v1.RIPEstatSource{ASN: 62371}},
		Pinned:    []string{"185.70.40.0/22"},
		Endpoints: []string{"mail-api.proton.me"},
	}
}

func cfgOf(t *testing.T, s v1.EgressRangesSpec) Config {
	t.Helper()
	c, err := ConfigFromSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func okObs(prefixes []string, ip string) *Observation {
	return &Observation{
		Source:   source.Result{Prefixes: ranges.MustNormalize(prefixes), RPKIVerified: true, Source: "test"},
		Resolved: map[string][]string{"mail-api.proton.me": {ip}},
	}
}

func unreachable() *Observation {
	return &Observation{FetchErr: fmt.Errorf("%w: boom", source.ErrUnreachable)}
}

func reasons(evs []Event) []string {
	var r []string
	for _, e := range evs {
		r = append(r, e.Reason)
	}
	return r
}

func hasReason(evs []Event, reason string) bool {
	for _, e := range evs {
		if e.Reason == reason {
			return true
		}
	}
	return false
}

func cond(st *v1.EgressRangesStatus, typ string) *metav1.Condition {
	return meta.FindStatusCondition(st.Conditions, typ)
}

// bootstrapped returns a status with enforced = pinned + 185.70.42.0/24.
func bootstrapped(t *testing.T, e *Engine, cfg Config, clk *fakeClock) *v1.EgressRangesStatus {
	t.Helper()
	st := &v1.EgressRangesStatus{}
	evs := e.Step(st, cfg, Annotations{}, okObs([]string{"185.70.42.0/24", "79.135.106.0/24"}, "185.70.42.41"), clk.Now(), 1)
	if !hasReason(evs, "Bootstrapped") {
		t.Fatalf("expected Bootstrapped, got %v", reasons(evs))
	}
	return st
}

func TestBootstrapSafeNoQuarantine(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	want := []string{"185.70.40.0/22", "185.70.42.0/24"}
	if !ranges.Equal(st.Enforced.CIDRs, want) {
		t.Fatalf("enforced=%v want %v", st.Enforced.CIDRs, want)
	}
	if st.Pending != nil {
		t.Fatal("bootstrap must not create pending")
	}
	if c := cond(st, v1.ConditionEndpointOutsideEnforced); c.Status != metav1.ConditionFalse {
		t.Fatalf("endpoint cond %v", c)
	}
}

func TestBootstrapModeAll(t *testing.T) {
	s := baseSpec()
	s.Mode = "all"
	cfg := cfgOf(t, s)
	st := &v1.EgressRangesStatus{}
	(&Engine{}).Step(st, cfg, Annotations{}, okObs([]string{"185.70.42.0/24", "79.135.106.0/24"}, "185.70.42.41"), t0, 1)
	if len(st.Enforced.CIDRs) != 3 {
		t.Fatalf("mode all enforced=%v", st.Enforced.CIDRs)
	}
}

func TestBootstrapUnsafeFallsBackToPinned(t *testing.T) {
	cfg := cfgOf(t, baseSpec())
	st := &v1.EgressRangesStatus{}
	// endpoint resolves outside every source prefix and outside pinned
	evs := (&Engine{}).Step(st, cfg, Annotations{}, okObs([]string{"79.135.106.0/24"}, "203.0.113.9"), t0, 1)
	if !hasReason(evs, "BootstrappedPinnedOnly") {
		t.Fatalf("events %v", reasons(evs))
	}
	if !ranges.Equal(st.Enforced.CIDRs, cfg.Pinned) {
		t.Fatalf("enforced=%v", st.Enforced.CIDRs)
	}
	if !hasReason(evs, ReasonUrgentEarly) {
		t.Fatalf("expected UrgentEarlyApproval, got %v", reasons(evs))
	}
}

func TestQuarantineOldOnlyThenPromoteAfter72h(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	old := append([]string{}, st.Enforced.CIDRs...)

	// Proton moves account endpoint into 185.70.43.0/24 => candidate gains one prefix
	obs := func() *Observation {
		o := okObs([]string{"185.70.42.0/24", "185.70.43.0/24"}, "185.70.42.41")
		o.Resolved["account.proton.me"] = []string{"185.70.43.10"}
		return o
	}
	clk.Advance(6 * time.Hour)
	evs := e.Step(st, cfg, Annotations{}, obs(), clk.Now(), 1)
	if !hasReason(evs, "QuarantineStarted") || st.Pending == nil {
		t.Fatalf("expected pending, events %v", reasons(evs))
	}
	if !ranges.Equal(st.Enforced.CIDRs, old) {
		t.Fatal("enforced must stay old-only during quarantine")
	}
	if got := st.Pending.PromoteAfter.Time; !got.Equal(clk.Now().Add(72 * time.Hour)) {
		t.Fatalf("promoteAfter %v", got)
	}
	if len(st.Pending.Added) != 1 || st.Pending.Added[0] != "185.70.43.0/24" {
		t.Fatalf("added %v", st.Pending.Added)
	}
	first := st.Pending.FirstSeen
	// polls every 6h for 66h: still pending, clock not reset
	for i := 0; i < 11; i++ {
		clk.Advance(6 * time.Hour)
		evs = e.Step(st, cfg, Annotations{}, obs(), clk.Now(), 1)
		if hasReason(evs, "Promoted") {
			t.Fatalf("promoted early at +%v", clk.Now().Sub(first.Time))
		}
		if !st.Pending.FirstSeen.Equal(&first) {
			t.Fatal("clock reset on identical digest")
		}
		if c := cond(st, v1.ConditionQuarantined); c.Status != metav1.ConditionTrue {
			t.Fatalf("Quarantined=%v", c.Status)
		}
	}
	clk.Advance(6 * time.Hour) // exactly 72h after firstSeen
	evs = e.Step(st, cfg, Annotations{}, obs(), clk.Now(), 1)
	if !hasReason(evs, "Promoted") {
		t.Fatalf("expected promotion at 72h, got %v", reasons(evs))
	}
	if st.Pending != nil || !ranges.ContainsAll(st.Enforced.CIDRs, []string{"185.70.43.0/24"}) {
		t.Fatalf("enforced=%v", st.Enforced.CIDRs)
	}
}

func TestRemovalsNotAppliedDuringQuarantine(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	s := baseSpec()
	s.Mode = "all"
	cfg := cfgOf(t, s)
	st := &v1.EgressRangesStatus{}
	e.Step(st, cfg, Annotations{}, okObs([]string{"185.70.42.0/24", "79.135.106.0/24", "79.135.107.0/24"}, "185.70.42.41"), clk.Now(), 1)
	clk.Advance(6 * time.Hour)
	e.Step(st, cfg, Annotations{}, okObs([]string{"185.70.42.0/24", "79.135.106.0/24"}, "185.70.42.41"), clk.Now(), 1)
	if st.Pending == nil || len(st.Pending.Removed) != 1 {
		t.Fatalf("pending %+v", st.Pending)
	}
	if !ranges.ContainsAll(st.Enforced.CIDRs, []string{"79.135.107.0/24"}) {
		t.Fatal("removed range dropped before quarantine elapsed")
	}
}

func TestDigestChangeResetsClock(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	a := func(ip string, extra ...string) *Observation {
		o := okObs(append([]string{"185.70.42.0/24"}, extra...), "185.70.42.41")
		o.Resolved["account.proton.me"] = []string{ip}
		return o
	}
	clk.Advance(time.Hour)
	e.Step(st, cfg, Annotations{}, a("185.70.43.1", "185.70.43.0/24", "79.135.106.0/24"), clk.Now(), 1)
	firstDigest := st.Pending.Digest
	clk.Advance(48 * time.Hour)
	evs := e.Step(st, cfg, Annotations{}, a("79.135.106.5", "185.70.43.0/24", "79.135.106.0/24"), clk.Now(), 1)
	if !hasReason(evs, "QuarantineReset") || st.Pending.Digest == firstDigest {
		t.Fatalf("expected reset, got %v", reasons(evs))
	}
	if !st.Pending.FirstSeen.Time.Equal(clk.Now()) {
		t.Fatal("firstSeen not reset")
	}
	resetAt := clk.Now()
	// 72h after the ORIGINAL firstSeen is only 25h after reset: no promotion
	clk.Advance(25 * time.Hour)
	evs = e.Step(st, cfg, Annotations{}, a("79.135.106.5", "185.70.43.0/24", "79.135.106.0/24"), clk.Now(), 1)
	if hasReason(evs, "Promoted") {
		t.Fatal("promoted on original clock")
	}
	clk.t = resetAt.Add(72 * time.Hour)
	evs = e.Step(st, cfg, Annotations{}, a("79.135.106.5", "185.70.43.0/24", "79.135.106.0/24"), clk.Now(), 1)
	if !hasReason(evs, "Promoted") {
		t.Fatalf("expected promotion 72h after reset, got %v", reasons(evs))
	}
}

func TestRevertClearsPending(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	o := okObs([]string{"185.70.42.0/24", "185.70.43.0/24"}, "185.70.42.41")
	o.Resolved["account.proton.me"] = []string{"185.70.43.1"}
	e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	if st.Pending == nil {
		t.Fatal("no pending")
	}
	evs := e.Step(st, cfg, Annotations{}, okObs([]string{"185.70.42.0/24"}, "185.70.42.41"), clk.Now(), 1)
	if st.Pending != nil || !hasReason(evs, "QuarantineCleared") {
		t.Fatalf("expected cleared, %v", reasons(evs))
	}
}

func TestNoPromotionWithoutFreshReconfirm(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	o := okObs([]string{"185.70.42.0/24", "185.70.43.0/24"}, "185.70.42.41")
	o.Resolved["account.proton.me"] = []string{"185.70.43.1"}
	e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	// source goes away for the rest of the quarantine
	for i := 0; i < 13; i++ {
		clk.Advance(6 * time.Hour)
		evs := e.Step(st, cfg, Annotations{}, unreachable(), clk.Now(), 1)
		if hasReason(evs, "Promoted") {
			t.Fatal("promoted while source unreachable")
		}
	}
	// annotation-only reconcile after 78h with stale lastConfirmed
	evs := e.Step(st, cfg, Annotations{}, nil, clk.Now(), 1)
	if hasReason(evs, "Promoted") || st.Pending == nil {
		t.Fatal("promoted with stale confirmation")
	}
	if c := cond(st, v1.ConditionNeedsApproval); c.Reason != "StaleConfirmation" {
		t.Fatalf("NeedsApproval reason %q", c.Reason)
	}
	// a fresh matching fetch promotes
	evs = e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	if !hasReason(evs, "Promoted") {
		t.Fatalf("expected promotion after re-confirm, %v", reasons(evs))
	}
}

func TestLargeChangeNeedsApprovalThenApprove(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk) // 2 enforced
	o := func() *Observation {
		ob := okObs([]string{"185.70.42.0/24", "79.135.106.0/24", "79.135.107.0/24"}, "185.70.42.41")
		ob.Resolved["a"] = []string{"79.135.106.1"}
		ob.Resolved["b"] = []string{"79.135.107.1"}
		return ob
	}
	evs := e.Step(st, cfg, Annotations{}, o(), clk.Now(), 1)
	if st.Pending == nil || !contains(st.Pending.SafetyFailures, CheckChangeTooLarge) {
		t.Fatalf("expected change gate, pending %+v", st.Pending)
	}
	if !hasReason(evs, "NeedsApproval") || cond(st, v1.ConditionNeedsApproval).Status != metav1.ConditionTrue {
		t.Fatalf("expected NeedsApproval, %v", reasons(evs))
	}
	clk.Advance(73 * time.Hour)
	evs = e.Step(st, cfg, Annotations{}, o(), clk.Now(), 1)
	if hasReason(evs, "Promoted") {
		t.Fatal("large change auto-promoted")
	}
	evs = e.Step(st, cfg, Annotations{ApproveDigest: st.Pending.Digest}, nil, clk.Now(), 1)
	if !hasReason(evs, "Promoted") {
		t.Fatalf("approval did not promote: %v", reasons(evs))
	}
}

func TestEarlyApprovalForMovedEndpoint(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	// mail-api moves to a ROA-valid prefix outside the enforced set
	o := okObs([]string{"185.70.42.0/24", "79.135.106.0/24"}, "79.135.106.20")
	clk.Advance(time.Hour)
	evs := e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	if !hasReason(evs, ReasonUrgentEarly) {
		t.Fatalf("expected UrgentEarlyApproval, %v", reasons(evs))
	}
	if c := cond(st, v1.ConditionEndpointOutsideEnforced); c.Status != metav1.ConditionTrue || !strings.Contains(c.Message, st.Pending.Digest) {
		t.Fatalf("cond %+v", c)
	}
	// no duplicate urgent event on next poll
	evs = e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	if hasReason(evs, ReasonUrgentEarly) {
		t.Fatal("duplicate urgent event")
	}
	// approval of the wrong digest does nothing
	evs = e.Step(st, cfg, Annotations{ApproveDigest: "sha256:nope"}, nil, clk.Now(), 1)
	if hasReason(evs, "Promoted") {
		t.Fatal("wrong digest promoted")
	}
	evs = e.Step(st, cfg, Annotations{ApproveDigest: st.Pending.Digest}, nil, clk.Now(), 1)
	if !hasReason(evs, "Promoted") {
		t.Fatalf("early approval failed %v", reasons(evs))
	}
	e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	if c := cond(st, v1.ConditionEndpointOutsideEnforced); c.Status != metav1.ConditionFalse {
		t.Fatal("endpoint still outside after promotion")
	}
}

func TestRejectDigest(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	o := okObs([]string{"185.70.42.0/24", "79.135.106.0/24"}, "185.70.42.41")
	o.Resolved["x"] = []string{"79.135.106.1"}
	e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	d := st.Pending.Digest
	evs := e.Step(st, cfg, Annotations{RejectDigest: d}, nil, clk.Now(), 1)
	if st.Pending != nil || !contains(st.RejectedDigests, d) || !hasReason(evs, "CandidateRejected") {
		t.Fatalf("reject failed: %v", reasons(evs))
	}
	clk.Advance(100 * time.Hour)
	e.Step(st, cfg, Annotations{RejectDigest: d}, o, clk.Now(), 1)
	if st.Pending != nil {
		t.Fatal("rejected digest became pending again")
	}
	if st.Enforced.Digest == d {
		t.Fatal("rejected digest enforced")
	}
	// explicit approve lifts the rejection; next fetch creates pending and promotes
	e.Step(st, cfg, Annotations{ApproveDigest: d}, o, clk.Now(), 1)
	if st.Enforced.Digest != d {
		t.Fatalf("approve after reject did not promote; pending=%+v", st.Pending)
	}
}

func TestUnreachableAlertAfter24h(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	enforced := st.Enforced.Digest
	alerts := 0
	for elapsed := time.Duration(0); elapsed < 30*time.Hour; elapsed += time.Hour {
		clk.Advance(time.Hour)
		evs := e.Step(st, cfg, Annotations{}, unreachable(), clk.Now(), 1)
		since := clk.Now().Sub(t0)
		c := cond(st, v1.ConditionSourceUnavailable)
		if c.Status != metav1.ConditionTrue {
			t.Fatal("SourceUnavailable not set")
		}
		if hasReason(evs, ReasonAlert24h) {
			alerts++
			if since != 24*time.Hour {
				t.Fatalf("alert at %v, want 24h", since)
			}
		}
		if since < 24*time.Hour && c.Reason == ReasonAlert24h {
			t.Fatalf("alert reason too early at %v", since)
		}
		if since >= 24*time.Hour && c.Reason != ReasonAlert24h {
			t.Fatalf("reason %q at %v", c.Reason, since)
		}
	}
	if alerts != 1 {
		t.Fatalf("alerts=%d want 1", alerts)
	}
	if st.Enforced.Digest != enforced || st.LastFetch.Result != v1.FetchUnreachable {
		t.Fatal("enforced changed during outage")
	}
	// recovery clears
	e.Step(st, cfg, Annotations{}, okObs([]string{"185.70.42.0/24"}, "185.70.42.41"), clk.Now(), 1)
	if c := cond(st, v1.ConditionSourceUnavailable); c.Status != metav1.ConditionFalse || st.ConsecutiveFailures != 0 {
		t.Fatal("not recovered")
	}
}

func TestInvalidNeverPending(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	e.Step(st, cfg, Annotations{}, &Observation{FetchErr: fmt.Errorf("%w: empty", source.ErrInvalid)}, clk.Now(), 1)
	if st.Pending != nil || st.LastFetch.Result != v1.FetchInvalid {
		t.Fatalf("invalid result handling: %+v", st.LastFetch)
	}
}

func TestDNSSECFailureFailsClosed(t *testing.T) {
	clk := &fakeClock{t0}
	e := &Engine{}
	cfg := cfgOf(t, baseSpec())
	st := bootstrapped(t, e, cfg, clk)
	o := okObs([]string{"185.70.42.0/24"}, "185.70.42.41")
	o.Resolved = nil
	o.DNSErr = errors.New("AD flag not set")
	e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	if st.Pending != nil {
		t.Fatal("DNSSEC failure created pending (would shrink to pinned)")
	}
	if c := cond(st, v1.ConditionNeedsApproval); c.Status != metav1.ConditionTrue || c.Reason != ReasonDNSSECFailed {
		t.Fatalf("NeedsApproval %+v", c)
	}
	if c := cond(st, v1.ConditionEndpointOutsideEnforced); c.Status != metav1.ConditionUnknown {
		t.Fatalf("endpoint cond %+v", c)
	}
}

func TestSafetyHardChecks(t *testing.T) {
	cfg := cfgOf(t, baseSpec())
	f := SafetyFailures(cfg, []string{"185.70.40.0/22"}, []string{"185.70.42.0/24"}, source.Result{Prefixes: []string{"185.70.42.0/24"}, RPKIVerified: true}, nil)
	if !contains(f, CheckPinnedRemoved) || !hasHard(f) {
		t.Fatalf("pinned removal not hard-failed: %v", f)
	}
	f = SafetyFailures(cfg, nil, nil, source.Result{}, nil)
	if !contains(f, CheckEmpty) {
		t.Fatalf("empty not failed: %v", f)
	}
	f = SafetyFailures(cfg, nil, []string{"185.70.40.0/22", "198.51.100.0/24"}, source.Result{Prefixes: []string{"185.70.42.0/24"}, RPKIVerified: true}, nil)
	if !contains(f, CheckNotRPKIValid) {
		t.Fatalf("non-RPKI prefix not flagged: %v", f)
	}
	// hard failure cannot be approved
	st := &v1.EgressRangesStatus{Enforced: v1.RangeSet{CIDRs: []string{"185.70.40.0/22"}, Digest: ranges.Digest([]string{"185.70.40.0/22"})}}
	st.Pending = &v1.PendingSet{CIDRs: []string{"185.70.42.0/24"}, Digest: ranges.Digest([]string{"185.70.42.0/24"}), FirstSeen: metav1.NewTime(t0), LastConfirmed: metav1.NewTime(t0), PromoteAfter: metav1.NewTime(t0), SafetyFailures: []string{CheckPinnedRemoved}}
	evs := (&Engine{}).Step(st, cfg, Annotations{ApproveDigest: st.Pending.Digest}, nil, t0, 1)
	if hasReason(evs, "Promoted") {
		t.Fatal("hard failure promoted via approval")
	}
}

func TestManualApprovalMode(t *testing.T) {
	clk := &fakeClock{t0}
	s := baseSpec()
	s.Approval.Mode = "manual"
	cfg := cfgOf(t, s)
	e := &Engine{}
	st := bootstrapped(t, e, cfg, clk)
	o := okObs([]string{"185.70.42.0/24", "185.70.43.0/24"}, "185.70.42.41")
	o.Resolved["a"] = []string{"185.70.43.3"}
	e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	clk.Advance(80 * time.Hour)
	if evs := e.Step(st, cfg, Annotations{}, o, clk.Now(), 1); hasReason(evs, "Promoted") {
		t.Fatal("manual mode auto-promoted")
	}
	if evs := e.Step(st, cfg, Annotations{ApproveDigest: st.Pending.Digest}, nil, clk.Now(), 1); !hasReason(evs, "Promoted") {
		t.Fatal("manual approval failed")
	}
}

func TestVerificationComposedRateLimitedAndNoReplyHold(t *testing.T) {
	clk := &fakeClock{t0}
	s := baseSpec()
	s.Verification = v1.Verification{Enabled: true, To: "noc@proton.ch", From: "ops@example.com"}
	s.Approval.NoReplyPolicy = "hold"
	cfg := cfgOf(t, s)
	e := &Engine{}
	st := bootstrapped(t, e, cfg, clk)
	o := okObs([]string{"185.70.42.0/24", "185.70.43.0/24"}, "185.70.42.41")
	o.Resolved["a"] = []string{"185.70.43.3"}
	evs := e.Step(st, cfg, Annotations{}, o, clk.Now(), 1)
	v := st.Pending.Verification
	if !hasReason(evs, "VerificationComposed") || v == nil || v.State != v1.VerificationComposed || v.To != "noc@proton.ch" {
		t.Fatalf("verification not composed: %+v", v)
	}
	for _, want := range []string{"Old ranges: 185.70.40.0/22, 185.70.42.0/24", "Added: 185.70.43.0/24", "First seen (UTC): 2026-10-27T12:00:00Z", "Can you confirm this change is intended?"} {
		if !strings.Contains(v.Body, want) {
			t.Fatalf("body missing %q:\n%s", want, v.Body)
		}
	}
	// a different digest within 7 days is rate limited
	o2 := okObs([]string{"185.70.42.0/24", "185.70.43.0/24", "79.135.106.0/24"}, "185.70.42.41")
	o2.Resolved["a"] = []string{"185.70.43.3"}
	o2.Resolved["b"] = []string{"79.135.106.3"}
	clk.Advance(time.Hour)
	evs = e.Step(st, cfg, Annotations{}, o2, clk.Now(), 1)
	if hasReason(evs, "VerificationComposed") || st.Pending.Verification.State != v1.VerificationSkipped {
		t.Fatalf("rate limit not applied: %v", st.Pending.Verification)
	}
	// back to o: new pending again, still rate limited; at 72h verification is
	// RateLimited (not NoReply), so it promotes; now test hold on a fresh one:
	st2 := bootstrapped(t, e, cfg, &fakeClock{t0})
	e.Step(st2, cfg, Annotations{}, o, t0, 1)
	evs = e.Step(st2, cfg, Annotations{}, o, t0.Add(72*time.Hour), 1)
	if hasReason(evs, "Promoted") || st2.Pending.Verification.State != v1.VerificationNoReply {
		t.Fatalf("no-reply hold not applied: %v %+v", reasons(evs), st2.Pending.Verification)
	}
	evs = e.Step(st2, cfg, Annotations{ApproveDigest: st2.Pending.Digest}, nil, t0.Add(72*time.Hour), 1)
	if !hasReason(evs, "Promoted") {
		t.Fatalf("confirmed reply did not promote: %v", reasons(evs))
	}
}

func TestVerificationDisabledByDefault(t *testing.T) {
	cfg := cfgOf(t, baseSpec())
	e := &Engine{}
	st := bootstrapped(t, e, cfg, &fakeClock{t0})
	o := okObs([]string{"185.70.42.0/24", "185.70.43.0/24"}, "185.70.42.41")
	o.Resolved["a"] = []string{"185.70.43.3"}
	evs := e.Step(st, cfg, Annotations{}, o, t0, 1)
	if hasReason(evs, "VerificationComposed") || st.Pending.Verification != nil {
		t.Fatal("verification ran while disabled")
	}
}

func TestScheduleJitterBackoffAndPromoteAfter(t *testing.T) {
	cfg := cfgOf(t, baseSpec())
	cfg.JitterPercent = 10
	e := &Engine{}
	st := &v1.EgressRangesStatus{}
	e.schedule(st, cfg, t0, true)
	if !st.NextFetch.Time.Equal(t0.Add(6 * time.Hour)) {
		t.Fatalf("no-jitter next %v", st.NextFetch)
	}
	for i := int32(1); i <= 8; i++ {
		st.ConsecutiveFailures = i
		e.schedule(st, cfg, t0, false)
		want := time.Minute << (i - 1)
		if want > 30*time.Minute {
			want = 30 * time.Minute
		}
		if got := st.NextFetch.Sub(t0); got != want {
			t.Fatalf("backoff %d = %v want %v", i, got, want)
		}
	}
	st.Pending = &v1.PendingSet{PromoteAfter: metav1.NewTime(t0.Add(2 * time.Hour))}
	e.schedule(st, cfg, t0, true)
	if !st.NextFetch.Time.Equal(t0.Add(2 * time.Hour)) {
		t.Fatalf("next fetch should align to promoteAfter, got %v", st.NextFetch)
	}
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	c := cfgOf(t, baseSpec())
	if c.PollInterval != 6*time.Hour || c.Quarantine != 72*time.Hour || c.UnreachableAlertAfter != 24*time.Hour || c.MaxChangeFraction != 0.5 || c.Mode != "minimal" {
		t.Fatalf("defaults %+v", c)
	}
	s := baseSpec()
	s.Approval.MaxChangeFraction = "2"
	if _, err := ConfigFromSpec(s); err == nil {
		t.Fatal("expected error")
	}
	s = baseSpec()
	s.Pinned = []string{"not-a-cidr"}
	if _, err := ConfigFromSpec(s); err == nil {
		t.Fatal("expected error")
	}
}
