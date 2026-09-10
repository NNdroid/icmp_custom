#!/usr/bin/env bash
# Local cross-compile helper — mirrors .github/workflows/release.yml so a
# release can be reproduced (and smoke-tested) on a dev machine before tagging.
#
# Usage:
#   ./scripts/build.sh [version]     # default version: dev
#
# Output: bin/icmp_custom-<version>-<os>-<arch>.tar.gz|.zip + checksums
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
  name="icmp_custom-${VERSION}-${goos}-${goarch}"
  out="bin/${name}"

  echo "==> building ${name}"
  mkdir -p "${out}"
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${out}/icmp_custom${ext}" .

  if [ "${goos}" = "windows" ]; then
    # zip exists on GitHub runners; fall back to Python's zipfile locally.
    if command -v zip >/dev/null 2>&1; then
      (cd bin && zip -qr "${name}.zip" "${name}")
    else
      # base_dir keeps the folder inside the archive, same as `zip -r`.
      (cd bin && python -c "import shutil,sys; shutil.make_archive(sys.argv[1],'zip',base_dir=sys.argv[1])" "${name}")
    fi
  else
    (cd bin && tar -czf "${name}.tar.gz" "${name}")
  fi
  rm -rf "${out}"
done

(cd bin && sha256sum * > checksums-sha256.txt)
echo "==> done: bin/"
ls -1 bin
