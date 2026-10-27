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

// Package engine is the pure quarantine/promotion state machine (spec sec. 4-5, 7).
// It has no Kubernetes client and takes time as an argument, so every rule is
// unit-testable with a fake clock.
package engine

import (
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
	"github.com/wscoble/egress-range-controller/internal/ranges"
	"github.com/wscoble/egress-range-controller/internal/source"
)

// Safety-check identifiers. Hard checks can never be overridden.
const (
	CheckEmpty            = "EmptySet"                 // hard
	CheckPinnedRemoved    = "PinnedRangeRemoved"       // hard
	CheckChangeTooLarge   = "ChangeExceedsMaxFraction" // soft (approve-digest overrides)
	CheckNotRPKIValid     = "PrefixNotRPKIValid"       // soft
	CheckEndpointOutside  = "EndpointOutsideCandidate" // soft
	CheckManualMode       = "ManualApprovalMode"       // soft
	CheckNoReplyHold      = "VerificationNoReplyHold"  // soft
	ReasonAlert24h        = "AlertUnreachable24h"
	ReasonUrgentEarly     = "UrgentEarlyApproval"
	ReasonDNSSECFailed    = "DNSSECValidationFailed"
	maxRejectedDigests    = 50
	maxFailureBackoff     = 30 * time.Minute
	initialFailureBackoff = time.Minute
)

var hardChecks = map[string]bool{CheckEmpty: true, CheckPinnedRemoved: true}

// Config is the defaulted view of the spec.
type Config struct {
	Pinned                []string
	Endpoints             []string
	Mode                  string
	Families              []string
	PollInterval          time.Duration
	JitterPercent         int32
	Quarantine            time.Duration
	UnreachableAlertAfter time.Duration
	MaxChangeFraction     float64
	ApprovalMode          string
	NoReplyPolicy         string
	Verification          v1.Verification
	VerificationInterval  time.Duration
	RequireRPKI           bool
}

func dur(d *metav1.Duration, def time.Duration) time.Duration {
	if d == nil || d.Duration <= 0 {
		return def
	}
	return d.Duration
}

// ConfigFromSpec applies defaults.
func ConfigFromSpec(s v1.EgressRangesSpec) (Config, error) {
	pinned, err := ranges.Normalize(s.Pinned)
	if err != nil {
		return Config{}, fmt.Errorf("spec.pinned: %w", err)
	}
	c := Config{
		Pinned:                pinned,
		Endpoints:             s.Endpoints,
		Mode:                  s.Mode,
		Families:              s.IPFamilies,
		PollInterval:          dur(s.PollInterval, 6*time.Hour),
		JitterPercent:         s.JitterPercent,
		Quarantine:            dur(s.QuarantinePeriod, 72*time.Hour),
		UnreachableAlertAfter: dur(s.UnreachableAlertAfter, 24*time.Hour),
		MaxChangeFraction:     0.5,
		ApprovalMode:          s.Approval.Mode,
		NoReplyPolicy:         s.Approval.NoReplyPolicy,
		Verification:          s.Verification,
		VerificationInterval:  dur(s.Verification.MinInterval, 7*24*time.Hour),
		RequireRPKI:           s.Source.Type == "" || s.Source.Type == v1.SourceRIPEstatRPKI,
	}
	if c.Mode == "" {
		c.Mode = "minimal"
	}
	if len(c.Families) == 0 {
		c.Families = []string{"IPv4"}
	}
	if c.ApprovalMode == "" {
		c.ApprovalMode = "auto"
	}
	if c.NoReplyPolicy == "" {
		c.NoReplyPolicy = "promote"
	}
	if s.Approval.MaxChangeFraction != "" {
		f, err := strconv.ParseFloat(s.Approval.MaxChangeFraction, 64)
		if err != nil || f < 0 || f > 1 {
			return Config{}, fmt.Errorf("spec.approval.maxChangeFraction %q invalid", s.Approval.MaxChangeFraction)
		}
		c.MaxChangeFraction = f
	}
	return c, nil
}

// Observation is the outcome of one fetch cycle (source + DNSSEC).
type Observation struct {
	// FetchErr is set when the source failed (wraps source.ErrUnreachable or source.ErrInvalid).
	FetchErr error
	Source   source.Result
	// Resolved maps endpoint -> addresses (DNSSEC-validated).
	Resolved map[string][]string
	// DNSErr is set if any endpoint failed validated resolution (fail closed).
	DNSErr error
}

// Annotations are the manual override inputs.
type Annotations struct {
	ApproveDigest string
	RejectDigest  string
}

// Event is something worth a Kubernetes Event / notification.
type Event struct {
	Type    string // Normal | Warning
	Reason  string
	Message string
}

// Engine evaluates one step.
type Engine struct {
	Rand *rand.Rand // jitter source; nil => no jitter
}

// Candidate computes the candidate set from a source result and resolved endpoints.
func Candidate(cfg Config, src source.Result, resolved map[string][]string) []string {
	if cfg.Mode == "all" {
		return ranges.Union(cfg.Pinned, src.Prefixes)
	}
	var sel []string
	for _, p := range src.Prefixes {
		for _, ips := range resolved {
			for _, ip := range ips {
				if ranges.Contains([]string{p}, ip) {
					sel = append(sel, p)
				}
			}
		}
	}
	return ranges.Union(cfg.Pinned, sel)
}

// SafetyFailures evaluates sec. 4 step 6 for candidate vs enforced.
func SafetyFailures(cfg Config, enforced, candidate []string, src source.Result, resolved map[string][]string) []string {
	var f []string
	if len(candidate) == 0 {
		f = append(f, CheckEmpty)
	}
	if !ranges.ContainsAll(candidate, cfg.Pinned) {
		f = append(f, CheckPinnedRemoved)
	}
	if len(enforced) > 0 && ranges.ChangeFraction(enforced, candidate) > cfg.MaxChangeFraction {
		f = append(f, CheckChangeTooLarge)
	}
	if cfg.RequireRPKI {
		valid := map[string]bool{}
		for _, p := range src.Prefixes {
			valid[p] = true
		}
		pinned := map[string]bool{}
		for _, p := range cfg.Pinned {
			pinned[p] = true
		}
		for _, c := range candidate {
			if !pinned[c] && (!valid[c] || !src.RPKIVerified) {
				f = append(f, CheckNotRPKIValid)
				break
			}
		}
	}
	for _, ips := range resolved {
		for _, ip := range ips {
			if !ranges.Contains(candidate, ip) {
				f = append(f, CheckEndpointOutside)
				goto done
			}
		}
	}
done:
	if cfg.ApprovalMode == "manual" && len(enforced) > 0 {
		f = append(f, CheckManualMode)
	}
	return f
}

func hasHard(fs []string) bool {
	for _, x := range fs {
		if hardChecks[x] {
			return true
		}
	}
	return false
}

func setCond(st *v1.EgressRangesStatus, typ string, status metav1.ConditionStatus, reason, msg string, now time.Time, gen int64) {
	meta.SetStatusCondition(&st.Conditions, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: msg,
		LastTransitionTime: metav1.NewTime(now), ObservedGeneration: gen,
	})
}

func condReason(st *v1.EgressRangesStatus, typ string) (metav1.ConditionStatus, string) {
	c := meta.FindStatusCondition(st.Conditions, typ)
	if c == nil {
		return metav1.ConditionUnknown, ""
	}
	return c.Status, c.Reason
}

func short(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// Step advances the state machine. obs == nil means "no fetch this reconcile"
// (e.g. an annotation changed): approvals and promotion are re-evaluated using
// the stored pending state and its freshness. It mutates st and returns events.
func (e *Engine) Step(st *v1.EgressRangesStatus, cfg Config, ann Annotations, obs *Observation, now time.Time, gen int64) []Event {
	var evs []Event
	emit := func(t, r, m string) { evs = append(evs, Event{Type: t, Reason: r, Message: m}) }
	nowT := metav1.NewTime(now)

	// --- Manual reject (always processed first) ---
	if d := ann.RejectDigest; d != "" && !contains(st.RejectedDigests, d) {
		st.RejectedDigests = append(st.RejectedDigests, d)
		if len(st.RejectedDigests) > maxRejectedDigests {
			st.RejectedDigests = st.RejectedDigests[len(st.RejectedDigests)-maxRejectedDigests:]
		}
		if st.Pending != nil && st.Pending.Digest == d {
			if st.Pending.Verification != nil {
				st.Pending.Verification.State = v1.VerificationDenied
			}
			emit("Warning", "CandidateRejected", fmt.Sprintf("pending %s rejected by annotation; discarded and will never be promoted", short(d)))
			st.Pending = nil
		} else {
			emit("Normal", "DigestRejected", fmt.Sprintf("digest %s added to rejected list", short(d)))
		}
	}
	// An explicit approval of a previously rejected digest lifts the rejection.
	if d := ann.ApproveDigest; d != "" && contains(st.RejectedDigests, d) {
		var keep []string
		for _, x := range st.RejectedDigests {
			if x != d {
				keep = append(keep, x)
			}
		}
		st.RejectedDigests = keep
	}

	if obs != nil {
		st.LastFetch = &v1.FetchStatus{Time: nowT, Source: obs.Source.Source}
		failErr := obs.FetchErr
		if failErr == nil && obs.DNSErr != nil && len(cfg.Endpoints) > 0 {
			failErr = fmt.Errorf("%s: %w", ReasonDNSSECFailed, obs.DNSErr)
		}
		if failErr != nil {
			evs = append(evs, e.onFailure(st, cfg, obs, failErr, now, gen)...)
			e.schedule(st, cfg, now, false)
			e.endpointCheck(st, nil, now, gen, &evs, failErr)
			return evs
		}
		// --- OK fetch ---
		st.ConsecutiveFailures = 0
		st.FirstFailure = nil
		st.LastSuccess = &nowT
		setCond(st, v1.ConditionSourceUnavailable, metav1.ConditionFalse, "FetchOK", obs.Source.Source, now, gen)

		cand := Candidate(cfg, obs.Source, obs.Resolved)
		dig := ranges.Digest(cand)
		st.LastFetch.Result = v1.FetchOK
		st.LastFetch.Candidate = cand
		st.LastFetch.CandidateDigest = dig
		st.LastFetch.ResolvedEndpoints = flatten(obs.Resolved)
		fails := SafetyFailures(cfg, st.Enforced.CIDRs, cand, obs.Source, obs.Resolved)

		switch {
		case len(st.Enforced.CIDRs) == 0:
			// Bootstrap: no quarantine on the very first set (documented). If the
			// candidate is unsafe we enforce only the pinned floor.
			if len(fails) == 0 {
				st.Enforced = v1.RangeSet{CIDRs: cand, Digest: dig, Since: &nowT}
				emit("Normal", "Bootstrapped", fmt.Sprintf("initial enforced set %s: %s", short(dig), strings.Join(cand, ",")))
			} else {
				st.Enforced = v1.RangeSet{CIDRs: cfg.Pinned, Digest: ranges.Digest(cfg.Pinned), Since: &nowT}
				emit("Warning", "BootstrappedPinnedOnly", fmt.Sprintf("candidate failed safety checks %v; enforcing pinned only", fails))
			}
			st.Pending = nil
			if len(st.Enforced.CIDRs) == 0 {
				// nothing pinned and unsafe candidate: stay empty (deny all), ask for help
				setCond(st, v1.ConditionNeedsApproval, metav1.ConditionTrue, CheckEmpty, "no safe initial set", now, gen)
			}
		case dig == st.Enforced.Digest:
			if st.Pending != nil {
				emit("Normal", "QuarantineCleared", fmt.Sprintf("source reverted to enforced %s; pending %s dropped", short(dig), short(st.Pending.Digest)))
			}
			st.Pending = nil
		case contains(st.RejectedDigests, dig):
			if st.Pending != nil {
				st.Pending = nil
			}
			if s, r := condReason(st, v1.ConditionQuarantined); !(s == metav1.ConditionFalse && r == "CandidateRejected") {
				emit("Warning", "RejectedCandidatePublished", fmt.Sprintf("source still publishes rejected digest %s", short(dig)))
			}
		default:
			if st.Pending == nil || st.Pending.Digest != dig {
				reason := "QuarantineStarted"
				if st.Pending != nil {
					reason = "QuarantineReset"
				}
				added, removed := ranges.Diff(st.Enforced.CIDRs, cand)
				st.Pending = &v1.PendingSet{
					CIDRs: cand, Digest: dig, FirstSeen: nowT, LastConfirmed: nowT,
					PromoteAfter: metav1.NewTime(now.Add(cfg.Quarantine)),
					Added:        added, Removed: removed,
					ChangeFraction: strconv.FormatFloat(ranges.ChangeFraction(st.Enforced.CIDRs, cand), 'f', 3, 64),
				}
				emit("Normal", reason, fmt.Sprintf("pending %s (+%v -%v); promote after %s", short(dig), added, removed, st.Pending.PromoteAfter.UTC().Format(time.RFC3339)))
				if v := e.composeVerification(st, cfg, now); v != nil {
					emit("Normal", "VerificationComposed", fmt.Sprintf("verification email to %s composed (NOT sent): %s", v.To, v.Subject))
				}
			} else {
				st.Pending.LastConfirmed = nowT
			}
			st.Pending.SafetyFailures = fails
		}
		e.schedule(st, cfg, now, true)
	}

	evs = append(evs, e.evaluatePromotion(st, cfg, ann, now, gen, obs != nil)...)
	var resolved map[string][]string
	if obs != nil {
		resolved = obs.Resolved
	}
	e.endpointCheck(st, resolved, now, gen, &evs, nil)
	st.ObservedGeneration = gen
	return evs
}

func (e *Engine) onFailure(st *v1.EgressRangesStatus, cfg Config, obs *Observation, err error, now time.Time, gen int64) []Event {
	var evs []Event
	nowT := metav1.NewTime(now)
	st.ConsecutiveFailures++
	if st.FirstFailure == nil {
		st.FirstFailure = &nowT
	}
	result := v1.FetchInvalid
	if errors.Is(err, source.ErrUnreachable) {
		result = v1.FetchUnreachable
	}
	st.LastFetch.Result = result
	st.LastFetch.Message = err.Error()

	since := st.FirstFailure.Time
	if st.LastSuccess != nil {
		since = st.LastSuccess.Time
	}
	reason := result
	if strings.HasPrefix(err.Error(), ReasonDNSSECFailed) {
		reason = ReasonDNSSECFailed
		setCond(st, v1.ConditionNeedsApproval, metav1.ConditionTrue, ReasonDNSSECFailed, err.Error(), now, gen)
	}
	if now.Sub(since) >= cfg.UnreachableAlertAfter {
		if _, r := condReason(st, v1.ConditionSourceUnavailable); r != ReasonAlert24h {
			evs = append(evs, Event{Type: "Warning", Reason: ReasonAlert24h,
				Message: fmt.Sprintf("no successful fetch since %s (%d consecutive failures): %v", since.UTC().Format(time.RFC3339), st.ConsecutiveFailures, err)})
		}
		reason = ReasonAlert24h
	}
	setCond(st, v1.ConditionSourceUnavailable, metav1.ConditionTrue, reason, err.Error(), now, gen)
	// Pending cannot be promoted without a fresh re-confirmation; enforced unchanged.
	return evs
}

func (e *Engine) evaluatePromotion(st *v1.EgressRangesStatus, cfg Config, ann Annotations, now time.Time, gen int64, fetched bool) []Event {
	var evs []Event
	if st.Pending == nil {
		setCond(st, v1.ConditionQuarantined, metav1.ConditionFalse, quarantineIdleReason(st), "no pending change", now, gen)
		// Only an OK fetch with a non-empty enforced set clears NeedsApproval;
		// annotation-only reconciles leave it as is.
		if fetched && len(st.Enforced.CIDRs) > 0 {
			setCond(st, v1.ConditionNeedsApproval, metav1.ConditionFalse, "NothingPending", "", now, gen)
		}
		return evs
	}
	p := st.Pending
	approved := ann.ApproveDigest != "" && ann.ApproveDigest == p.Digest
	fresh := now.Sub(p.LastConfirmed.Time) <= cfg.PollInterval
	timeUp := !now.Before(p.PromoteAfter.Time)
	fails := append([]string{}, p.SafetyFailures...)

	if p.Verification != nil {
		switch {
		case approved:
			p.Verification.State = v1.VerificationConfirmed
		case timeUp && p.Verification.State == v1.VerificationComposed:
			p.Verification.State = v1.VerificationNoReply
		}
		if p.Verification.State == v1.VerificationNoReply && cfg.NoReplyPolicy == "hold" && !approved {
			fails = append(fails, CheckNoReplyHold)
		}
	}

	hard := hasHard(fails)
	promote := fresh && !hard && (approved || (timeUp && len(fails) == 0))
	if promote {
		how := "quarantine elapsed"
		if approved {
			how = "approved by annotation"
		}
		old := st.Enforced.Digest
		nowT := metav1.NewTime(now)
		st.Enforced = v1.RangeSet{CIDRs: p.CIDRs, Digest: p.Digest, Since: &nowT}
		st.Pending = nil
		evs = append(evs, Event{Type: "Normal", Reason: "Promoted", Message: fmt.Sprintf("enforced %s -> %s (%s): %s", short(old), short(p.Digest), how, strings.Join(p.CIDRs, ","))})
		setCond(st, v1.ConditionQuarantined, metav1.ConditionFalse, "Promoted", "", now, gen)
		setCond(st, v1.ConditionNeedsApproval, metav1.ConditionFalse, "Promoted", "", now, gen)
		return evs
	}

	msg := fmt.Sprintf("pending %s until %s", short(p.Digest), p.PromoteAfter.UTC().Format(time.RFC3339))
	setCond(st, v1.ConditionQuarantined, metav1.ConditionTrue, "InQuarantine", msg, now, gen)
	if len(fails) > 0 || (timeUp && !fresh) {
		reason := "StaleConfirmation"
		if len(fails) > 0 {
			reason = fails[0]
		}
		amsg := fmt.Sprintf("pending %s blocked by %v; approve with: kubectl annotate egr <name> %s=%s --overwrite", short(p.Digest), fails, v1.AnnotationApproveDigest, p.Digest)
		if hard {
			amsg = fmt.Sprintf("pending %s fails hard check %v and cannot be promoted", short(p.Digest), fails)
		}
		if s, r := condReason(st, v1.ConditionNeedsApproval); !(s == metav1.ConditionTrue && r == reason) && len(fails) > 0 {
			evs = append(evs, Event{Type: "Warning", Reason: "NeedsApproval", Message: amsg})
		}
		setCond(st, v1.ConditionNeedsApproval, metav1.ConditionStatus(boolStatus(len(fails) > 0)), reason, amsg, now, gen)
	} else {
		setCond(st, v1.ConditionNeedsApproval, metav1.ConditionFalse, "Quarantining", "", now, gen)
	}
	return evs
}

func boolStatus(b bool) metav1.ConditionStatus {
	if b {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

func quarantineIdleReason(st *v1.EgressRangesStatus) string {
	if st.LastFetch != nil && st.LastFetch.CandidateDigest != "" && contains(st.RejectedDigests, st.LastFetch.CandidateDigest) && st.LastFetch.CandidateDigest != st.Enforced.Digest {
		return "CandidateRejected"
	}
	return "InSync"
}

// endpointCheck sets EndpointOutsideEnforced. resolved==nil keeps the previous
// value unless failErr says DNSSEC failed (then Unknown).
func (e *Engine) endpointCheck(st *v1.EgressRangesStatus, resolved map[string][]string, now time.Time, gen int64, evs *[]Event, failErr error) {
	if resolved == nil {
		if failErr != nil && strings.HasPrefix(failErr.Error(), ReasonDNSSECFailed) {
			setCond(st, v1.ConditionEndpointOutsideEnforced, metav1.ConditionUnknown, ReasonDNSSECFailed, failErr.Error(), now, gen)
		}
		return
	}
	var outside []string
	for _, h := range sortedKeys(resolved) {
		for _, ip := range resolved[h] {
			if !ranges.Contains(st.Enforced.CIDRs, ip) {
				outside = append(outside, h+"="+ip)
			}
		}
	}
	if len(outside) == 0 {
		setCond(st, v1.ConditionEndpointOutsideEnforced, metav1.ConditionFalse, "AllInside", "", now, gen)
		return
	}
	msg := fmt.Sprintf("endpoints outside enforced set: %s", strings.Join(outside, ","))
	if st.Pending != nil {
		msg += fmt.Sprintf("; to approve early: kubectl annotate egr <name> %s=%s --overwrite", v1.AnnotationApproveDigest, st.Pending.Digest)
	}
	if s, _ := condReason(st, v1.ConditionEndpointOutsideEnforced); s != metav1.ConditionTrue {
		*evs = append(*evs, Event{Type: "Warning", Reason: ReasonUrgentEarly, Message: msg})
	}
	setCond(st, v1.ConditionEndpointOutsideEnforced, metav1.ConditionTrue, ReasonUrgentEarly, msg, now, gen)
}

// schedule sets NextFetch: poll interval with jitter on success; capped
// exponential backoff on failure; never later than a pending promoteAfter.
func (e *Engine) schedule(st *v1.EgressRangesStatus, cfg Config, now time.Time, ok bool) {
	var d time.Duration
	if ok {
		d = cfg.PollInterval
		if e.Rand != nil && cfg.JitterPercent > 0 {
			span := int64(cfg.PollInterval) * int64(cfg.JitterPercent) / 100
			d += time.Duration(e.Rand.Int63n(2*span+1) - span)
		}
	} else {
		d = initialFailureBackoff << min(int(st.ConsecutiveFailures)-1, 10)
		if d > maxFailureBackoff {
			d = maxFailureBackoff
		}
		if d > cfg.PollInterval {
			d = cfg.PollInterval
		}
	}
	next := now.Add(d)
	if st.Pending != nil && st.Pending.PromoteAfter.After(now) && st.Pending.PromoteAfter.Time.Before(next) {
		next = st.Pending.PromoteAfter.Time
	}
	t := metav1.NewTime(next)
	st.NextFetch = &t
}

func (e *Engine) composeVerification(st *v1.EgressRangesStatus, cfg Config, now time.Time) *v1.VerificationRequest {
	if !cfg.Verification.Enabled || st.Pending == nil {
		return nil
	}
	p := st.Pending
	id := fmt.Sprintf("%s-%d", short(p.Digest), p.FirstSeen.Unix())
	if st.LastVerificationAt != nil && now.Sub(st.LastVerificationAt.Time) < cfg.VerificationInterval {
		p.Verification = &v1.VerificationRequest{ID: id, State: v1.VerificationSkipped, To: cfg.Verification.To}
		return nil
	}
	nowT := metav1.NewTime(now)
	st.LastVerificationAt = &nowT
	subject := fmt.Sprintf("Verification request: published prefix change observed [ref %s]", id)
	var b strings.Builder
	fmt.Fprintf(&b, "Hello,\n\nI run a client behind an egress allowlist that tracks your published address ranges. ")
	fmt.Fprintf(&b, "My controller observed a change and is holding it in quarantine until it is confirmed.\n\n")
	fmt.Fprintf(&b, "First seen (UTC): %s\n", p.FirstSeen.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Source: %s\n", sourceOf(st))
	fmt.Fprintf(&b, "Old ranges: %s\n", strings.Join(st.Enforced.CIDRs, ", "))
	fmt.Fprintf(&b, "New ranges: %s\n", strings.Join(p.CIDRs, ", "))
	fmt.Fprintf(&b, "Added: %s\nRemoved: %s\n\n", joinOrNone(p.Added), joinOrNone(p.Removed))
	fmt.Fprintf(&b, "Can you confirm this change is intended?\n\nThank you.\nReference: %s\n", id)
	v := &v1.VerificationRequest{ID: id, State: v1.VerificationComposed, To: cfg.Verification.To, From: cfg.Verification.From, Subject: subject, Body: b.String(), ComposedAt: &nowT}
	p.Verification = v
	return v
}

func sourceOf(st *v1.EgressRangesStatus) string {
	if st.LastFetch != nil && st.LastFetch.Source != "" {
		return st.LastFetch.Source + " + DNSSEC-validated endpoint lookups"
	}
	return "configured source"
}

func joinOrNone(x []string) string {
	if len(x) == 0 {
		return "(none)"
	}
	return strings.Join(x, ", ")
}

func flatten(m map[string][]string) []string {
	var out []string
	for _, h := range sortedKeys(m) {
		for _, ip := range m[h] {
			out = append(out, h+"="+ip)
		}
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
