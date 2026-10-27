# Design

## Problem

A third-party client (the motivating case is Proton Mail Bridge) runs in a pod with
a default-deny egress policy plus an allowlist of the vendor's IP ranges. The
allowlist has to follow the vendor's real network, and it must not become a
way to open egress to an attacker who can influence a feed or DNS.

## Sources of truth and how they are used

| Signal | Source | Use |
|---|---|---|
| Announced prefixes | RIPEstat `announced-prefixes?resource=AS<n>` | Raw candidates. |
| RPKI origin validation | RIPEstat `rpki-validation?resource=AS<n>&prefix=<p>` (routinator) | **Required**: `status == valid` and a validating ROA with `origin == n` and `validity == valid`. |
| Endpoint addresses | A/AAAA over DNSSEC-validating resolvers (AD bit, DO set, DoT by default) | **Required check**: every endpoint IP must fall in the candidate. In `minimal` mode, it also selects which prefixes are kept. |
| Pinned ranges | `spec.pinned` | Always enforced; their removal is a hard failure. |

A failure in any per-prefix RPKI lookup fails the whole fetch (Unreachable or
Invalid). A partial view is never treated as the provider's list.

## State machine (`internal/engine`)

`engine.Step(status, config, annotations, observation, now)` is a pure function.
It takes no clients or clocks, and every rule below has a fake-clock unit test.

1. **Annotations.** `reject-digest` adds the digest to `rejectedDigests` and discards a matching pending set.
   `approve-digest` lifts a rejection of that digest.
2. **Failed observation** (fetch error, or DNSSEC failure while endpoints are configured):
   - increment `consecutiveFailures` and set `SourceUnavailable`
   - emit `AlertUnreachable24h` once, `unreachableAlertAfter` after the last success
   - leave pending untouched, so it can't promote without a fresh confirm
   - schedule a backoff
3. **Bootstrap** (nothing enforced): enforce `pinned ∪ candidate` if it's safe, otherwise `pinned`.
4. **Same as enforced:** clear pending.
5. **New digest:** start a quarantine (`firstSeen = now`, `promoteAfter = now + quarantinePeriod`).
   A different digest from the current pending **resets** the clock.
   The same digest refreshes `lastConfirmed`.
6. **Promotion** requires all of:
   - `now − lastConfirmed ≤ pollInterval` (fresh)
   - no hard failures (`EmptySet`, `PinnedRangeRemoved`)
   - either an approve annotation for this digest, or the time is up and no soft failures
     (`ChangeExceedsMaxFraction`, `PrefixNotRPKIValid`, `EndpointOutsideCandidate`,
     `ManualApprovalMode`, `VerificationNoReplyHold`)
7. **Otherwise** `NeedsApproval` explains why, with the `kubectl annotate` command.
8. **Endpoint check against the enforced set:** `EndpointOutsideEnforced` and a one-shot
   `UrgentEarlyApproval` warning.

Scheduling: `pollInterval ± jitter`. On failure, `1m·2^(n-1)` capped at 30m (and
at the poll interval). The next fetch is never later than a future `promoteAfter`.

## Failure modes

| Situation | Behavior |
|---|---|
| Source unreachable or timed out | Enforced unchanged; `SourceUnavailable`; backoff; alert after 24h. Pending can't promote without a fresh confirm. |
| Garbage or empty response | Invalid; never becomes pending. |
| Endpoint moves to a new IP mid-quarantine | Client may fail (closed, no leak); `EndpointOutsideEnforced` + `UrgentEarlyApproval`; approve the digest early. |
| Hijacked feed adds a foreign range | Fails RPKI. If it's RPKI-valid but unusual, it waits out the quarantine in the open, and large diffs need approval. |
| Controller down | Policy stays as last rendered. |
| DNSSEC validation fails | Treated as a failed observation: nothing changes, `NeedsApproval/DNSSECValidationFailed`. |

## Rendering (`internal/render`)

One owned NetworkPolicy (controller owner reference) per `EgressRanges` object:
- `policyTypes: [Egress]`
- the kube-dns rule
- one ipBlock rule with `status.enforced` and the configured ports

It's rendered only from `status.enforced`, never from pending. The digest is
recorded in the `egress.greybeard.support/rendered-digest` annotation.

## Verification request

Optional. It composes a message for the provider's NOC per new digest, rate-limited
to one per `minInterval`, into `status.pending.verification` and an Event. There's
no delivery code in the controller. That's a deliberate boundary: an egress
controller shouldn't also be a mail client. The answer is recorded with
approve/reject. NoReply at the quarantine's end is governed by `noReplyPolicy`.

## Decisions that differ from the first draft

- **Generic names.** Group `egress.greybeard.support`, kind `EgressRanges`, metrics
  `egress_range_*`. The first draft had `ProtonEgressRanges` in `mail.greybeard.support`.
- **DoT resolvers by default.** On the build machine, plain UDP/53 to public resolvers
  was intercepted and answered without AD with a fake address. The controller
  correctly failed closed. Over DoT it got the real, AD-validated answer.
- **Controller clock, not API-server timestamps.** The times are persisted in status,
  so restarts don't reset the quarantine.
- **Approval overrides only soft checks.**
- **Not a singleton.** Any number of `EgressRanges` objects per namespace, each owning one policy.

## First live fetch (2026-10-27)

See [dry-run-2026-10-27.json](dry-run-2026-10-27.json). Summary:
- **DNSSEC (AD, DoT):** mail-api.proton.me → 185.70.42.41; account.proton.me → 185.70.42.36.
- **RPKI-valid AS62371 IPv4 prefixes (13):**
  - 79.135.106.0/24, 79.135.107.0/24
  - 95.36.96.0/24, 95.36.98.0/24
  - 109.224.244.0/24, 109.224.247.0/24
  - 176.119.200.0/24
  - 185.70.40.0/24, 185.70.41.0/24, 185.70.42.0/24, 185.70.43.0/24
  - 185.205.70.0/24
  - 194.0.147.0/24
- **Candidate (minimal):** `185.70.40.0/22`, `185.70.42.0/24`
  (`sha256:c699e68e58f47d5522a6e46438807246e592bf6512e67811af3bdccb2f810d7d`).
  The /24 is inside the pinned /22. It's kept so the digest reflects the ROA.
