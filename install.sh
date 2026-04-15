#!/usr/bin/env bash
# install.sh — Install system and Python dependencies for log_forwarder_benchmark.py
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*" >&2; }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "Run as root:  sudo ./install.sh"
  exit 1
fi

echo -e "\n${GREEN}=== SAP Log Forwarder — Dependency Installer ===${NC}\n"

# ── Detect package manager ────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
  PKG_MGR="apt-get"
  UPDATE_CMD="apt-get update -qq"
  INSTALL_CMD="apt-get install -y -qq"
elif command -v yum &>/dev/null; then
  PKG_MGR="yum"
  UPDATE_CMD="yum check-update -q || true"
  INSTALL_CMD="yum install -y -q"
elif command -v dnf &>/dev/null; then
  PKG_MGR="dnf"
  UPDATE_CMD="dnf check-update -q || true"
  INSTALL_CMD="dnf install -y -q"
else
  err "No supported package manager found (apt/yum/dnf)"
  exit 1
fi

ok "Package manager: $PKG_MGR"
echo "Updating package index..."
$UPDATE_CMD

# ── System packages ───────────────────────────────────────────────────────────
SYSTEM_PKGS=(
  "netcat-openbsd"   # nc  — UDP log forwarding
  "openssh-client"   # scp/ssh — Wazuh file transfer
  "expect"           # password-based SSH automation
  "python3"
  "python3-pip"
)

echo "Installing system packages..."
for pkg in "${SYSTEM_PKGS[@]}"; do
  if $INSTALL_CMD "$pkg" &>/dev/null; then
    ok "$pkg"
  else
    # Fallback name for yum/dnf
    alt="${pkg/netcat-openbsd/nmap-ncat}"
    if $INSTALL_CMD "$alt" &>/dev/null; then
      ok "$alt (fallback)"
    else
      warn "Could not install $pkg — you may need to install it manually"
    fi
  fi
done

# ── Python packages ───────────────────────────────────────────────────────────
echo "Installing Python packages..."
pip3 install -q -r "$(dirname "$0")/requirements.txt" && ok "Python requirements"

# ── Verify critical commands ──────────────────────────────────────────────────
echo ""
echo "Verifying installed commands:"
REQUIRED_CMDS=(nc scp ssh expect python3)
ALL_OK=true
for cmd in "${REQUIRED_CMDS[@]}"; do
  if command -v "$cmd" &>/dev/null; then
    ok "$cmd → $(command -v "$cmd")"
  else
    err "$cmd NOT FOUND"
    ALL_OK=false
  fi
done

echo ""
if $ALL_OK; then
  ok "All dependencies satisfied. You're ready to run:"
  echo "   python3 log_forwarder_benchmark.py --config config.yaml"
else
  err "Some dependencies are missing. Resolve the errors above before running."
  exit 1
fi
