#!/usr/bin/env bash
# Builds the distroless image for linux/amd64 and linux/arm64 WITHOUT a
# container runtime (uses crane and a throwaway local registry), then saves:
#   dist/egress-range-controller_<v>.oci.tar               multi-arch OCI archive
#   dist/egress-range-controller_<v>_linux-<arch>.docker.tar  per-arch docker archives
# Import on k3s: sudo k3s ctr images import dist/egress-range-controller_<v>.oci.tar
set -euo pipefail
VERSION="${VERSION:-0.1.0}"
IMAGE="${IMAGE:-ghcr.io/wscoble/egress-range-controller}"
BASE="${BASE:-gcr.io/distroless/static:nonroot}"
PORT="${PORT:-5055}"
OUT="${OUT:-dist}"
command -v crane >/dev/null || { echo "crane is required (go install github.com/google/go-containerregistry/cmd/crane@latest)"; exit 1; }
mkdir -p "$OUT"; work="$(mktemp -d)"
crane registry serve --address "127.0.0.1:${PORT}" >"$work/registry.log" 2>&1 & reg=$!
trap 'kill $reg 2>/dev/null; rm -rf "$work"' EXIT
sleep 1
R="127.0.0.1:${PORT}/egress-range-controller"
for arch in amd64 arm64; do
  mkdir -p "$work/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags='-s -w -buildid=' -o "$work/$arch/egress-range-controller" ./cmd
  tar --owner=0 --group=0 --numeric-owner --mtime='2026-01-01 00:00:00Z' -C "$work/$arch" -cf "$work/$arch.tar" egress-range-controller
  crane append --insecure --platform "linux/$arch" -b "$BASE" -f "$work/$arch.tar" -t "$R:$VERSION-$arch" >/dev/null
  crane mutate --insecure "$R:$VERSION-$arch" --entrypoint=/egress-range-controller --user=65532:65532 --workdir=/ \
    -l org.opencontainers.image.source=https://github.com/wscoble/egress-range-controller \
    -l org.opencontainers.image.version="$VERSION" -l org.opencontainers.image.licenses=Apache-2.0 \
    -t "$R:$VERSION-$arch" >/dev/null
  crane pull --insecure "$R:$VERSION-$arch" "$work/$arch.docker.tar"
  mkdir "$work/$arch.d" && tar -C "$work/$arch.d" -xf "$work/$arch.docker.tar"
  python3 - "$work/$arch.d/manifest.json" "$IMAGE:$VERSION" <<'PY'
import json,sys; p,t=sys.argv[1:]; j=json.load(open(p)); j[0]["RepoTags"]=[t]; json.dump(j,open(p,"w"))
PY
  tar --owner=0 --group=0 --numeric-owner --sort=name -C "$work/$arch.d" -cf "$OUT/egress-range-controller_${VERSION}_linux-$arch.docker.tar" .
  echo "linux/$arch manifest: $(crane digest --insecure "$R:$VERSION-$arch")"
done
crane index append --insecure -m "$R:$VERSION-amd64" -m "$R:$VERSION-arm64" -t "$R:$VERSION" >/dev/null
crane pull --insecure --format=oci "$R:$VERSION" "$work/oci"
python3 - "$work/oci/index.json" "$IMAGE:$VERSION" "$VERSION" <<'PY'
import json,sys; p,name,v=sys.argv[1:]; j=json.load(open(p))
for m in j["manifests"]:
    m.setdefault("annotations",{}).update({"org.opencontainers.image.ref.name":v,"io.containerd.image.name":name})
json.dump(j,open(p,"w"))
PY
tar --owner=0 --group=0 --numeric-owner --sort=name -C "$work/oci" -cf "$OUT/egress-range-controller_${VERSION}.oci.tar" .
echo "index digest: $(crane digest --insecure "$R:$VERSION")"
ls -l "$OUT"/*.tar
