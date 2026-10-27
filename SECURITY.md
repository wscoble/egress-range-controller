# Security policy

## Reporting a vulnerability
Please **don't** open a public issue. Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on
https://github.com/wscoble/egress-range-controller.

Include the version, your configuration (redact anything private), and steps to
reproduce. We aim to acknowledge within 5 business days.

## Supported versions
Only the latest minor release gets fixes while the project is pre-1.0.

## In scope
- Any way to get a CIDR into `status.enforced` / the rendered NetworkPolicy that
  bypasses the quarantine, the RPKI check, the pinned-range rules, or approval.
- DNSSEC validation bypasses (accepting answers without the AD bit when required).
- RBAC or NetworkPolicy defaults that grant more than documented.

## Out of scope
- The trust you place in your resolvers, in RIPEstat, or in your own `static`/`url`
  source. See "Security model and limitations" in the README.
- Clusters whose CNI doesn't enforce NetworkPolicy.
