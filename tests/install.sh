#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/hapsigner-install-test.XXXXXX")"
trap 'rm -rf "${WORKDIR}"' EXIT

bash "${REPO_ROOT}/install.sh" \
  --source "${REPO_ROOT}" \
  --prefix "${WORKDIR}/source-prefix"
test -x "${WORKDIR}/source-prefix/bin/hap-sign"
"${WORKDIR}/source-prefix/bin/hap-sign" --version | grep -q '^hap-sign '

asset_root="${WORKDIR}/assets"
stage="${WORKDIR}/stage"
mkdir -p "${asset_root}" "${stage}"
cp "${WORKDIR}/source-prefix/bin/hap-sign" "${stage}/hap-sign"
asset="hap-sign-x86_64-unknown-linux-gnu.tar.gz"
tar -C "${stage}" -czf "${asset_root}/${asset}" hap-sign
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${asset_root}/${asset}" >"${asset_root}/${asset}.sha256"
else
  shasum -a 256 "${asset_root}/${asset}" >"${asset_root}/${asset}.sha256"
fi

bash "${REPO_ROOT}/install.sh" \
  --prefix "${WORKDIR}/release-prefix" \
  --target x86_64-unknown-linux-gnu \
  --download-base-url "file://${asset_root}"
test -x "${WORKDIR}/release-prefix/bin/hap-sign"
"${WORKDIR}/release-prefix/bin/hap-sign" --version | grep -q '^hap-sign '

echo "installer tests passed"
