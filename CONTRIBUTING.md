# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Ground rules
- This controller sits on a security boundary. Changes that make it easier for a
  new range to reach the enforced set (shorter quarantine, skipped checks, new
  sources) need a clear threat-model note in the PR description.
- Keep the engine (`internal/engine`) pure: no clients, no clocks, no I/O. Every
  behavior change there needs a fake-clock test.
- No outbound messaging code (SMTP, chat) in the controller. Verification requests
  are composed into status and Events; delivery is the operator's choice.

## Dev loop
```sh
make test lint          # go test, go vet, gofmt, helm lint, kustomize build
make generate           # after editing api/v1alpha1 (CRD + deepcopy + chart CRD)
make deploy-bundle      # regenerate deploy/all.yaml
make dry-run            # live fetch with the built-in Proton example; no cluster access
```
Requirements: Go (see `go.mod`), helm 3, kustomize 5, and optionally crane for
`make image-tarball`.

## Commits
- Sign off your commits (`git commit -s`, Developer Certificate of Origin).
- One logical change per PR. Run `make check-generated` before pushing.

By contributing you agree your contributions are licensed under Apache-2.0.
