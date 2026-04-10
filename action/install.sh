#!/usr/bin/env bash
# Copyright 2025 venslabs
# SPDX-License-Identifier: Apache-2.0
#
# Installs the vens binary for the current GitHub Actions runner.
# Reads the following environment variables:
#   VENS_VERSION       - Version to install (e.g. "v0.3.1" or "latest"). Default: "latest".
#   VENS_INSTALL_DIR   - Directory to install vens into. Default: "${RUNNER_TOOL_CACHE}/vens/<version>/<arch>".
#   GH_TOKEN           - Optional GitHub token used to resolve "latest" without API rate limits.
#
# Appends the install directory to $GITHUB_PATH and writes the resolved version
# to the `version` output of the calling step.

set -euo pipefail

log() { printf '[vens-action] %s\n' "$*"; }
die() { printf '::error::[vens-action] %s\n' "$*" >&2; exit 1; }

: "${VENS_VERSION:=latest}"
: "${VENS_INSTALL_DIR:=}"

REPO="venslabs/vens"

# --- detect OS and ARCH -------------------------------------------------------

uname_s=$(uname -s)
uname_m=$(uname -m)

case "${uname_s}" in
  Linux)  os="linux"  ;;
  Darwin) os="darwin" ;;
  *)      die "unsupported OS: ${uname_s}" ;;
esac

case "${uname_m}" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) die "unsupported architecture: ${uname_m}" ;;
esac

log "detected platform: ${os}/${arch}"

# --- early cache hit: pre-installed vens --------------------------------------
#
# If the caller provided an explicit install-dir that already contains a vens
# binary, we skip the download and GitHub API resolution entirely. This enables
# two use cases:
#   1. "Bring your own vens": users who build vens from source, mirror releases
#      internally, or pin to a specific commit SHA can drop the binary into a
#      known location and pass `install-dir:` to the action.
#   2. Self-testing: the action's own CI workflow builds vens from the current
#      source tree before invoking the action, to validate changes that are
#      not yet part of a published release.

if [[ -n "${VENS_INSTALL_DIR}" && -x "${VENS_INSTALL_DIR}/vens" ]]; then
  log "vens already present at ${VENS_INSTALL_DIR} — skipping download"
  echo "${VENS_INSTALL_DIR}" >> "${GITHUB_PATH}"
  resolved_version=$("${VENS_INSTALL_DIR}/vens" --version 2>/dev/null | awk '{print $NF}' || true)
  if [[ -z "${resolved_version}" ]]; then
    resolved_version="${VENS_VERSION}"
  fi
  echo "version=${resolved_version}" >> "${GITHUB_OUTPUT}"
  log "vens ${resolved_version} ready at ${VENS_INSTALL_DIR}/vens"
  exit 0
fi

# --- resolve version ----------------------------------------------------------

resolve_latest() {
  local api="https://api.github.com/repos/${REPO}/releases/latest"
  local auth_header=()
  if [[ -n "${GH_TOKEN:-}" ]]; then
    auth_header=(-H "Authorization: Bearer ${GH_TOKEN}")
  fi
  curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "${auth_header[@]}" \
    "${api}" \
    | grep -o '"tag_name": *"[^"]*"' \
    | head -n1 \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

if [[ "${VENS_VERSION}" == "latest" ]]; then
  log "resolving latest release from ${REPO}..."
  VENS_VERSION=$(resolve_latest || true)
  if [[ -z "${VENS_VERSION}" ]]; then
    die "failed to resolve the latest vens release; pin an explicit version with \`with.version\`."
  fi
  log "resolved latest => ${VENS_VERSION}"
fi

# Normalise version: ensure it starts with "v"
case "${VENS_VERSION}" in
  v*) ;;
  *)  VENS_VERSION="v${VENS_VERSION}" ;;
esac

# Strip leading "v" for tarball path component
version_noV="${VENS_VERSION#v}"

# --- download and verify ------------------------------------------------------

tarball="vens-${VENS_VERSION}-${os}-${arch}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${VENS_VERSION}"
tar_url="${base_url}/${tarball}"
sums_url="${base_url}/SHA256SUMS"

if [[ -z "${VENS_INSTALL_DIR}" ]]; then
  cache_root="${RUNNER_TOOL_CACHE:-${HOME}/.cache}/vens/${version_noV}/${arch}"
  VENS_INSTALL_DIR="${cache_root}/bin"
fi

mkdir -p "${VENS_INSTALL_DIR}"

if [[ -x "${VENS_INSTALL_DIR}/vens" ]]; then
  log "vens ${VENS_VERSION} already installed at ${VENS_INSTALL_DIR} — reusing cache"
else
  workdir=$(mktemp -d)
  trap 'rm -rf "${workdir}"' EXIT

  log "downloading ${tar_url}"
  curl -fsSL --retry 3 --retry-delay 2 -o "${workdir}/${tarball}" "${tar_url}" \
    || die "failed to download ${tar_url} — check that version ${VENS_VERSION} exists"

  log "downloading ${sums_url}"
  if curl -fsSL --retry 3 --retry-delay 2 -o "${workdir}/SHA256SUMS" "${sums_url}"; then
    expected=$(grep -F "${tarball}" "${workdir}/SHA256SUMS" | awk '{print $1}' || true)
    if [[ -z "${expected}" ]]; then
      die "tarball ${tarball} not listed in SHA256SUMS"
    fi
    actual=$(sha256sum "${workdir}/${tarball}" | awk '{print $1}')
    if [[ "${expected}" != "${actual}" ]]; then
      die "checksum mismatch for ${tarball} (expected ${expected}, got ${actual})"
    fi
    log "SHA256 verified: ${actual}"
  else
    log "::warning:: SHA256SUMS not found at ${sums_url}; skipping checksum verification"
  fi

  log "extracting to ${VENS_INSTALL_DIR}"
  tar -xzf "${workdir}/${tarball}" -C "${VENS_INSTALL_DIR}"
  chmod +x "${VENS_INSTALL_DIR}/vens"
fi

# --- export to subsequent steps -----------------------------------------------

echo "${VENS_INSTALL_DIR}" >> "${GITHUB_PATH}"
echo "version=${VENS_VERSION}" >> "${GITHUB_OUTPUT}"

log "vens ${VENS_VERSION} ready at ${VENS_INSTALL_DIR}/vens"
"${VENS_INSTALL_DIR}/vens" --version || true
