# egress-range-controller

A small Kubernetes controller that keeps an **egress NetworkPolicy** in sync with
a provider's **published IP ranges**, without trusting any single feed. New ranges
are **verified** (RPKI origin validation, DNSSEC-validated endpoint checks) and
then **quarantined** for 72 hours before they're enforced.

It was built to lock [Proton Mail Bridge](https://proton.me/mail/bridge) pods down
to Proton's own network (AS62371). It works for any provider whose ranges you can
get from RIPEstat, a static list, or an HTTPS URL.

> Status: v0.1.0, pre-1.0. The API group is `egress.greybeard.support/v1alpha1`.

## Why

An allowlist egress policy for a third-party client is a good containment
control: if the client (or its image) is compromised, it can't talk to anything
but its vendor. But providers add and move ranges. A hand-maintained list goes
stale and breaks things. A list that blindly follows a feed can be pointed
anywhere by whoever controls the feed.

This controller sits in between:

- **Fail closed.** If the feed is down, returns garbage, or DNSSEC validation fails,
  nothing changes. The NetworkPolicy stays as last rendered and nothing opens.
- **Only allows; never shrinks pinned ranges; never renders an empty set.**
- **Every change waits.** A new set is enforced only after it has been stable for the
  quarantine period, re-confirmed by a fresh fetch, and passed the safety checks.
  Large changes need a human.

## How it works

Each poll (default every 6h ±10% jitter, with exponential backoff on failure)
the controller:

1. **Fetches** prefixes from the source. For `ripestat-rpki`, that means RIPEstat
   `announced-prefixes` for the ASN, then `rpki-validation` for each prefix. Only
   prefixes with an RPKI-**valid** ROA whose origin is the ASN are kept.
2. **Resolves** each `endpoint` hostname through DNSSEC-validating resolvers
   (DNS-over-TLS by default). It requires the AD bit and fails closed.
3. **Builds the candidate**: `pinned` ∪ either the prefixes that contain a
   resolved endpoint IP (`mode: minimal`) or all valid prefixes (`mode: all`).
4. **Compares** the candidate's digest with the enforced set and runs the state
   machine below.
5. **Renders** the owned NetworkPolicy from `status.enforced` *only*: kube-dns
   on 53 plus the enforced CIDRs on the configured ports (default TCP 443).

### Quarantine

```
                 candidate == enforced
   ┌──────────────────────────────────────────────┐
   ▼                                              │
[Enforced] ──new digest──► [Pending: firstSeen=now, promoteAfter=now+72h]
                                │  same digest re-fetched → lastConfirmed=now
                                │  different digest       → clock RESETS
                                │  reject annotation      → discarded, never promoted
                                ▼
         now ≥ promoteAfter AND lastConfirmed is fresh (≤ 1 poll interval)
         AND no safety check fails             ──► promoted to Enforced
         OR approve-digest annotation matches
         AND no *hard* check fails             ──► promoted early
```

- During quarantine **only the old set is enforced**, including for removals.
  A range that disappears from the feed stays allowed until the change promotes.
- **Bootstrap.** With nothing enforced yet, the controller enforces `pinned ∪
  candidate` immediately if the candidate passes the checks. Otherwise it enforces
  `pinned` only. There's no quarantine on first install.
- **Safety checks.** Hard checks can never be approved past: an empty set, or a
  pinned range removed. Soft checks block automatic promotion but can be
  overridden by an approve annotation:
  - change fraction > `maxChangeFraction` (default 0.5)
  - a prefix that isn't RPKI-valid
  - an endpoint outside the candidate
  - `approval.mode: manual`
  - a verification with no reply under `noReplyPolicy: hold`

### Conditions, events, metrics

| Condition | Meaning |
|---|---|
| `Synced` | NetworkPolicy rendered from `status.enforced` |
| `Quarantined` | a pending set is waiting (see `status.pending.promoteAfter`) |
| `SourceUnavailable` | the last fetch failed (Unreachable or Invalid) |
| `EndpointOutsideEnforced` | a resolved endpoint IP isn't in the enforced set; the client is probably broken right now |
| `NeedsApproval` | a pending set can't promote on its own; the message carries the exact `kubectl annotate` command |

Warning events to alert on:
- `AlertUnreachable24h`: no successful fetch for `unreachableAlertAfter`.
- `UrgentEarlyApproval`: an endpoint moved outside the enforced set; consider approving the pending digest early.
- `NeedsApproval`, `CandidateRejected`, `BootstrappedPinnedOnly`, `RejectedCandidatePublished`.

Normal events: `Bootstrapped`, `QuarantineStarted`, `QuarantineReset`, `Promoted`,
`QuarantineCleared`, `DigestRejected`, `VerificationComposed`.

Prometheus metrics on `:8080/metrics`:
- `egress_range_needs_approval`
- `egress_range_quarantined`
- `egress_range_source_unavailable`
- `egress_range_source_unreachable_alert`
- `egress_range_endpoint_outside_enforced`
- `egress_range_enforced_cidrs`
- `egress_range_pending_promote_after_seconds`
- `egress_range_last_success_timestamp_seconds`
- `egress_range_fetch_total{result}`

An optional `notifyWebhook` gets a JSON POST for warnings and state changes.

### Approving or rejecting

```sh
kubectl -n mail get egressranges default -o jsonpath='{.status.pending.digest}{"\n"}'
kubectl -n mail annotate egressranges default egress.greybeard.support/approve-digest=sha256:... --overwrite
kubectl -n mail annotate egressranges default egress.greybeard.support/reject-digest=sha256:...  --overwrite
```

An annotation only acts on the exact digest it names. A rejected digest is
remembered in `status.rejectedDigests` (last 50) and is never promoted unless you
later approve that same digest.

### Verification request (optional, off by default)

With `verification.enabled: true`, each new pending digest gets a short, polite
"did your ranges change?" message for the provider's NOC. It lists old/new/added/removed,
first-seen time (UTC), and the source. The message goes into `status.pending.verification`
and a `VerificationComposed` event. It's rate-limited to one per `minInterval`
(default 7 days). **The controller never sends it.** It contains no mail code.
Send it yourself or wire it to your own tooling. Record the answer with the
approve/reject annotations. For Proton, the published network contact (tech-c on
AS62371's RIPE record) is `noc@proton.ch`.

## Quickstart: Helm

```sh
helm install egress-range-controller ./charts/egress-range-controller \
  --namespace mail \
  -f charts/egress-range-controller/examples/proton-values.yaml \
  --set 'controllerNetworkPolicy.apiServer.cidrs={10.43.0.1/32,<API-ENDPOINT-IP>/32}'
kubectl -n mail get egressranges
```

The controller runs **in the same namespace as the pods it protects**. Its RBAC
is namespaced.

## Quickstart: Kustomize

```sh
# edit the 192.0.2.10/32 placeholder in config/network-policy/controller-egress.yaml first
kustomize build config/overlays/proton-example | kubectl apply -f -
```

- `config/default`: namespace (PSA `restricted`), CRD, RBAC, controller NetworkPolicy, Deployment.
- `config/overlays/proton-example`: namespace `mail`, the Proton `EgressRanges`.
- `config/overlays/static-example`: a static CIDR list for `app=example`, with a target default-deny.
- `config/components/target-default-deny`: opt-in default-deny egress for the target pods.

A pre-rendered bundle for the Proton example is in `deploy/all.yaml`
(`make deploy-bundle`).

### Deploy from an image tarball (air-gapped / k3s)

```sh
make image-tarball                  # dist/egress-range-controller_0.1.0.oci.tar (amd64+arm64)
sudo k3s ctr images import dist/egress-range-controller_0.1.0.oci.tar
kubectl apply -f deploy/all.yaml    # imagePullPolicy: IfNotPresent
```

### Rollback

The rendered policy has an owner reference to the `EgressRanges` object, so
**deleting the object deletes the policy**. If a default-deny is in place, that
cuts the target off (fail closed).

```sh
# Stop the controller but keep the last rendered policy exactly as it is:
kubectl -n mail scale deploy/egress-range-controller --replicas=0
# Remove the controller completely and keep the policy:
kubectl -n mail delete egressranges default --cascade=orphan
kubectl -n mail delete -f deploy/all.yaml --ignore-not-found   # or: helm uninstall
# ...then re-apply your hand-maintained policy if you want it back.
# Revert to a previously enforced set: approve that digest while it's pending,
# or edit spec.source / spec.pinned (that change is quarantined like any other).
```

### Adopting an existing policy

If a NetworkPolicy named `spec.networkPolicy.name` already exists, the controller
takes it over on the first reconcile and **replaces its rules with the bootstrap set**.
In minimal mode that may be narrower than a hand-written list. Use `mode: all`, or
add your current ranges to `pinned`, if you need a no-change cut-over.

## Configuration reference

All fields live on the `EgressRanges` spec. The Helm values have the same names under `egressRanges.*`.

| Setting | Field | Default | Notes |
|---|---|---|---|
| Poll interval | `pollInterval` | `6h` | ±`jitterPercent` (10%). Backoff on failure: 1m, 2m, 4m… capped at 30m. |
| Quarantine duration | `quarantinePeriod` | `72h` | Measured from `status.pending.firstSeen`; resets when the digest changes. |
| Unreachable alert | `unreachableAlertAfter` | `24h` | Fires `AlertUnreachable24h` once per outage. |
| Prefix source | `source.type` | `ripestat-rpki` | `ripestat-rpki`, `static`, or `url`. |
| RPKI source | `source.ripestat.asn` / `.baseURL` / `.sourceApp` | — / `https://stat.ripe.net` / `egress-range-controller` | Keeps only RPKI-valid prefixes with origin = ASN. |
| Pinned ranges | `pinned` | `[]` | Always enforced, never removed by the controller. |
| Endpoints | `endpoints` | `[]` | Hostnames that must resolve (DNSSEC) inside the set. |
| Mode | `mode` | `minimal` | `minimal` = pinned + prefixes containing an endpoint; `all` = pinned + all valid prefixes. |
| IP families | `ipFamilies` | `[IPv4]` | Add `IPv6` to include v6 prefixes. |
| DNSSEC resolvers | `dnssec.resolvers` | `tls://1.1.1.1:853#cloudflare-dns.com`, `tls://9.9.9.9:853#dns.quad9.net` | `ip:port` (UDP/TCP) or `tls://ip:853#servername` (DoT). Tried in order. |
| DNSSEC validation | `dnssec.requireAD` | `true` | Rejects answers without the AD bit. Fails closed. |
| DNS timeout | `dnssec.timeout` | `5s` | Per query. |
| Approval mode | `approval.mode` | `auto` | `manual` means every change needs the approve annotation. |
| Approval threshold | `approval.maxChangeFraction` | `"0.5"` | (added+removed)/len(enforced). Above this, NeedsApproval. |
| No-reply policy | `approval.noReplyPolicy` | `promote` | `hold` blocks auto-promotion while a verification is unanswered. |
| Notifier / allowlist email | `verification.enabled` / `.to` / `.from` / `.minInterval` | `false` / — / — / `168h` | Composes only; never sends. Helm: `egressRanges.notifier.*`. |
| Webhook | `notifyWebhook` | `""` | JSON POST. Allow its egress with `controllerNetworkPolicy.extraEgress`. |
| Policy name | `networkPolicy.name` | `proton-bridge-egress-allow` (CRD) / `egress-allow` (chart) | Keep in sync with the RBAC `resourceNames` (Helm does this). |
| Target pods | `networkPolicy.podSelector` | — | Required. |
| Ports | `networkPolicy.ports` | `TCP 443` | Applied to the enforced CIDRs. |
| DNS rule | `networkPolicy.allowDNS` | `true` | Adds kube-dns UDP/TCP 53. |

Chart-only values:
- `controllerNetworkPolicy.apiServer.cidrs` / `.ports`: kube API egress for the controller. Set it to your Service IP **and** endpoint IP.
- `controllerNetworkPolicy.resolverCIDRs`, `.sourceCIDRs` / `.sourceExcept`, `.extraEgress`.
- `targetDefaultDeny.enabled`, `namespace.create`.
- `image.*` (`repository`, `tag`, `digest`, `pullPolicy`), `resources`, `leaderElection.enabled`.

## Using your own IP source

- **Static list:** `source: {type: static, static: {cidrs: [...]}}`. Changes go
  through the same quarantine when you edit the list.
- **HTTPS URL:** `source: {type: url, url: {url: https://example.com/ranges.txt}}`.
  The file is one CIDR or IP per line, and `#` starts a comment. Only `https://` is accepted.
- **RIPEstat for another ASN:** set `source.ripestat.asn`.

For `static` and `url` sources there's no RPKI check. **The quarantine and the
approval threshold are your only protection**, so prefer `approval.mode: manual`
for feeds you don't control. To add a source type, implement `source.Fetcher` in
`internal/source` and add tests that use recorded responses.

## Security model and limitations

What it protects against:
- **A hijacked or wrong feed** adding foreign ranges. They fail RPKI. If they're
  RPKI-valid but odd, they wait out the quarantine in the open, with an event and
  metric, and big diffs need a human.
- **DNS spoofing** of endpoints: AD bit required, over DoT by default.
- **Feed outages:** nothing changes, and you get alerted.

What it doesn't do:
- **NetworkPolicy only allows.** You need a default-deny egress policy for the target
  pods (`targetDefaultDeny.enabled` or your own), and a CNI that enforces policy.
  On k3s, kube-router enforces it unless the cluster runs `--disable-network-policy`.
- **It isn't a content filter.** Anything inside the allowed ranges is reachable,
  including other customers of a cloud provider's ranges.
- **Trust anchors.** You trust RIPEstat's validator (routinator) and your DNSSEC
  resolvers. A resolver that lies about the AD bit defeats the endpoint check.
- **Controller egress is broad by design.** NetworkPolicy can't match hostnames, so the
  controller may reach any public IPv4 on 443 to talk to RIPEstat. Narrow it with
  `controllerNetworkPolicy.sourceCIDRs` (stat.ripe.net was in RIPE NCC's
  193.0.0.0/21 as of 2026-10-27).
- **Clock.** Times are taken from the controller's clock and persisted in status.
  A restart doesn't reset the quarantine, but large clock skew on the node shifts it.
- **RBAC.** `list`/`watch`/`create` on NetworkPolicies can't be limited by name, so
  the controller can create other policies in its namespace. Updates are limited
  to the one rendered policy. Anyone with `patch` on `egressranges` can approve.
- **Single replica** with leader election. If the controller is down, the policy
  stays static.

## Development

```sh
make test          # unit tests (fake clock, httptest RIPEstat fixtures, local DNS server, fake client)
make lint          # vet, gofmt, helm lint/template, kustomize build
make dry-run       # live fetch with the built-in Proton example; prints JSON; no cluster access
```

See [docs/design.md](docs/design.md) for the design and
[docs/dry-run-2026-10-27.json](docs/dry-run-2026-10-27.json) for a real first fetch.

## License

Apache-2.0. Copyright 2026 Greybeard Holdings LLC. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
