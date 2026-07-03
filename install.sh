#!/usr/bin/env bash
# Install the open-source scanners claude-security orchestrates.
# Everything is optional at runtime — the tool skips missing scanners — but
# installing more means broader coverage. Versions are pinned for reproducible
# results; bump them deliberately.
#
# Prefer the Docker path (see README) if you'd rather not install natively.
set -uo pipefail

SEMGREP_VER="1.168.0"
BANDIT_VER="1.8.6"
CHECKOV_VER="3.2.470"
OSV_VER="2.2.3"          # osv-scanner
TRIVY_VER="0.67.2"
GITLEAKS_VER="8.28.0"
TRUFFLEHOG_VER="3.90.9"
GOSEC_VER="2.22.9"
SCHEMATHESIS_VER="4.4.5"

info() { printf '\033[36m[install]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[skip]\033[0m %s\n' "$1"; }
ok()   { printf '\033[32m[ok]\033[0m %s\n' "$1"; }

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# ---- Python-based scanners (pip) -------------------------------------------
if command -v pip3 >/dev/null 2>&1; then
  info "installing Python scanners via pip"
  pip3 install --quiet \
    "semgrep==${SEMGREP_VER}" \
    "bandit==${BANDIT_VER}" \
    "checkov==${CHECKOV_VER}" \
    "schemathesis==${SCHEMATHESIS_VER}" \
    && ok "semgrep, bandit, checkov, schemathesis"
  # AI triage SDK + config parsing
  pip3 install --quiet anthropic pyyaml && ok "anthropic SDK, pyyaml"
else
  warn "pip3 not found — skipping Python scanners"
fi

# ---- Go-based / binary scanners --------------------------------------------
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"
export PATH="$BIN_DIR:$PATH"

install_gitleaks() {
  case "$ARCH" in x86_64) A=x64;; aarch64|arm64) A=arm64;; *) A="$ARCH";; esac
  local url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_${OS}_${A}.tar.gz"
  info "gitleaks ${GITLEAKS_VER}"
  curl -fsSL "$url" | tar xz -C "$BIN_DIR" gitleaks 2>/dev/null \
    && ok "gitleaks -> $BIN_DIR" || warn "gitleaks download failed"
}

install_trivy() {
  info "trivy ${TRIVY_VER}"
  curl -fsSL "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" \
    | sh -s -- -b "$BIN_DIR" "v${TRIVY_VER}" >/dev/null 2>&1 \
    && ok "trivy -> $BIN_DIR" || warn "trivy install failed"
}

install_osv() {
  case "$ARCH" in x86_64) A=amd64;; aarch64|arm64) A=arm64;; *) A="$ARCH";; esac
  local url="https://github.com/google/osv-scanner/releases/download/v${OSV_VER}/osv-scanner_${OS}_${A}"
  info "osv-scanner ${OSV_VER}"
  curl -fsSL "$url" -o "$BIN_DIR/osv-scanner" 2>/dev/null \
    && chmod +x "$BIN_DIR/osv-scanner" && ok "osv-scanner -> $BIN_DIR" \
    || warn "osv-scanner download failed"
}

install_trufflehog() {
  info "trufflehog ${TRUFFLEHOG_VER}"
  curl -fsSL "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh" \
    | sh -s -- -b "$BIN_DIR" "v${TRUFFLEHOG_VER}" >/dev/null 2>&1 \
    && ok "trufflehog -> $BIN_DIR" || warn "trufflehog install failed"
}

install_gosec() {
  if command -v go >/dev/null 2>&1; then
    info "gosec ${GOSEC_VER} (via go install)"
    go install "github.com/securego/gosec/v2/cmd/gosec@v${GOSEC_VER}" >/dev/null 2>&1 \
      && ok "gosec (in \$GOPATH/bin)" || warn "gosec install failed"
  else
    warn "go toolchain not found — skipping gosec (only needed for Go repos)"
  fi
}

if command -v curl >/dev/null 2>&1; then
  install_gitleaks
  install_trivy
  install_osv
  install_trufflehog
  install_gosec
else
  warn "curl not found — cannot fetch binary scanners"
fi

# ---- eslint-plugin-security is per-project ---------------------------------
warn "eslint-security uses the target repo's own eslint + eslint-plugin-security config; not installed globally"

echo
ok "done. Run: python3 scripts/scan.py <repo>"
echo "Add $BIN_DIR to your PATH if it isn't already:  export PATH=\"$BIN_DIR:\$PATH\""
