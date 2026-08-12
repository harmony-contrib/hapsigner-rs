#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${HAPSIGNER_REPO_URL:-https://github.com/harmony-contrib/hapsigner-rs}"
VERSION="${HAPSIGNER_VERSION:-v0.1.0}"
PREFIX="${HAPSIGNER_PREFIX:-${HOME}/.local}"
DOWNLOAD_BASE_URL="${HAPSIGNER_DOWNLOAD_BASE_URL:-}"
GITHUB_TOKEN="${HAPSIGNER_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
TARGET="${HAPSIGNER_TARGET:-auto}"
SOURCE_DIR=""
FORCE=0

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Install the Java-free OpenHarmony HAP signer.

Options:
  --prefix DIR       Install prefix. Default: $HOME/.local
  --version TAG      Release tag. Default: v0.1.0
  --repo URL         Release repository. Default: https://github.com/harmony-contrib/hapsigner-rs
  --target TARGET    Rust host target, or auto
  --download-base-url URL
                     Download URL containing release assets
  --source DIR       Build and install from a local checkout
  --force            Replace an existing binary
  -h, --help         Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --repo) REPO_URL="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --download-base-url) DOWNLOAD_BASE_URL="${2:-}"; shift 2 ;;
    --source) SOURCE_DIR="${2:-}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

detect_target() {
  local os arch
  case "$(uname -s)" in
    Linux) os=unknown-linux-gnu ;;
    Darwin) os=apple-darwin ;;
    MINGW*|MSYS*|CYGWIN*) os=pc-windows-msvc ;;
    *) echo "unsupported host platform: $(uname -s)" >&2; exit 2 ;;
  esac
  case "$(uname -m)" in
    arm64|aarch64) arch=aarch64 ;;
    x86_64|amd64) arch=x86_64 ;;
    *) echo "unsupported host architecture: $(uname -m)" >&2; exit 2 ;;
  esac
  printf '%s-%s\n' "${arch}" "${os}"
}

download() {
  local url="$1" output="$2"
  if command -v curl >/dev/null 2>&1; then
    if [ -n "${GITHUB_TOKEN}" ]; then
      curl -fL --retry 3 -H "Authorization: Bearer ${GITHUB_TOKEN}" -o "${output}" "${url}"
    else
      curl -fL --retry 3 -o "${output}" "${url}"
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ -n "${GITHUB_TOKEN}" ]; then
      wget --header="Authorization: Bearer ${GITHUB_TOKEN}" -O "${output}" "${url}"
    else
      wget -O "${output}" "${url}"
    fi
  else
    echo "curl or wget is required" >&2
    exit 1
  fi
}

verify_checksum() {
  local checksum_file="$1" archive="$2" expected actual
  expected="$(awk 'NR == 1 { print $1 }' "${checksum_file}")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${archive}" | awk '{ print $1 }')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${archive}" | awk '{ print $1 }')"
  else
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
  if [ -z "${expected}" ] || [ "${expected}" != "${actual}" ]; then
    echo "release checksum mismatch" >&2
    exit 1
  fi
}

if [ -z "${PREFIX}" ]; then
  usage >&2
  exit 2
fi
if [ "${TARGET}" = auto ]; then
  TARGET="$(detect_target)"
fi

case "${TARGET}" in
  *-pc-windows-msvc) binary_name=hap-sign.exe ;;
  *) binary_name=hap-sign ;;
esac

install_dir="${PREFIX}/bin"
destination="${install_dir}/${binary_name}"
if [ -e "${destination}" ] && [ "${FORCE}" != 1 ]; then
  echo "binary already exists: ${destination}; use --force to replace it" >&2
  exit 1
fi
mkdir -p "${install_dir}"

if [ -n "${SOURCE_DIR}" ]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required with --source" >&2
    exit 1
  fi
  cargo build --release --locked --manifest-path "${SOURCE_DIR}/Cargo.toml"
  install -m 0755 "${SOURCE_DIR}/target/release/${binary_name}" "${destination}"
else
  asset="hap-sign-${TARGET}.tar.gz"
  if [ -n "${DOWNLOAD_BASE_URL}" ]; then
    base_url="${DOWNLOAD_BASE_URL%/}"
  else
    base_url="${REPO_URL%/}/releases/download/${VERSION}"
  fi
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/hapsigner-install.XXXXXX")"
  trap 'rm -rf "${temporary}"' EXIT
  download "${base_url}/${asset}" "${temporary}/${asset}"
  download "${base_url}/${asset}.sha256" "${temporary}/${asset}.sha256"
  verify_checksum "${temporary}/${asset}.sha256" "${temporary}/${asset}"
  tar -xzf "${temporary}/${asset}" -C "${temporary}"
  if [ ! -f "${temporary}/${binary_name}" ]; then
    echo "release archive does not contain ${binary_name}" >&2
    exit 1
  fi
  install -m 0755 "${temporary}/${binary_name}" "${destination}"
fi

echo "installed: ${destination}"
case ":${PATH}:" in
  *":${install_dir}:"*) ;;
  *) echo "add ${install_dir} to PATH" ;;
esac
