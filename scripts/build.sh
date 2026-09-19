#!/usr/bin/env bash
# Local cross-compile helper — mirrors .github/workflows/release.yml so a
# release can be reproduced (and smoke-tested) on a dev machine before tagging.
#
# Usage:
#   ./scripts/build.sh [version]     # default version: dev
#
# Output: bin/icmp_custom-<version>-<os>-<arch>[.exe] + checksums-sha256.txt
# Binaries are emitted directly, never wrapped in an archive - the release
# publishes them as assets by name, so the wrapper would only add an unpack
# step and a second hash to keep in step.
set -euo pipefail

VERSION="${1:-dev}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

TARGETS=(
  "linux 386"
  "linux amd64"
  "linux arm"
  "linux arm64"
  "linux loong64"
  "linux riscv64"
  "darwin amd64"
  "darwin arm64"
  "freebsd amd64"
  "windows amd64"
  "windows arm64"
  "android arm64"
)

rm -rf bin
mkdir -p bin

for target in "${TARGETS[@]}"; do
  read -r goos goarch <<<"${target}"
  ext=""
  [ "${goos}" = "windows" ] && ext=".exe"
  out="bin/icmp_custom-${VERSION}-${goos}-${goarch}${ext}"

  echo "==> building ${out##*/}"
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${out}" .
done

(cd bin && sha256sum * > checksums-sha256.txt)
echo "==> done: bin/"
ls -1 bin
