#!/bin/sh
# install.sh — user-level install for agent-receipts-daemon on Linux.
# Usage: curl -fsSL https://github.com/agent-receipts/ar/releases/latest/download/install.sh | sh
#
# Installs to ~/.local/bin, sets up the systemd user unit, and generates the
# signing key if one does not already exist. Safe to re-run for upgrades.
#
# Wrapping everything in main() guards against partial execution when the
# download is truncated mid-stream while piped to sh.

set -eu

REPO="agent-receipts/obsigna"
INSTALL_DIR="${HOME}/.local/bin"
# KEY_FILE is the XDG default path. The installer targets the default install layout;
# custom AGENTRECEIPTS_KEY or XDG_DATA_HOME overrides are out of scope here.
KEY_FILE="${HOME}/.local/share/agent-receipts/signing.key"
UNIT_DIR="${HOME}/.config/systemd/user"
UNIT_NAME="agent-receipts-daemon.service"
BASHRC="${HOME}/.bashrc"

# Set at the top so the EXIT trap is always safe to evaluate.
WORK_DIR=""
STARTED=0
trap '[ -n "$WORK_DIR" ] && rm -rf -- "$WORK_DIR"' EXIT

step() { printf '\n==> %s\n' "$*"; }
die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }

main() {
  # Linux only
  [ "$(uname -s)" = "Linux" ] || \
    die "Linux only. For macOS: brew install agent-receipts/tap/obsigna"

  # Require systemd
  command -v systemctl >/dev/null 2>&1 || \
    die "systemctl not found — this installer requires systemd"

  # sha256sum for checksum verification (part of coreutils, present on all mainstream distros)
  command -v sha256sum >/dev/null 2>&1 || \
    die "sha256sum not found — install coreutils and retry"

  # Map uname -m to GoReleaser arch labels
  case "$(uname -m)" in
    x86_64)        GOARCH=amd64 ;;
    aarch64|arm64) GOARCH=arm64 ;;
    *)             die "Unsupported architecture: $(uname -m)" ;;
  esac

  # Resolve latest stable obsigna release.
  # The repo has multiple component release trains (sdk/go/v*, mcp-proxy/v*,
  # obsigna/v*) so we filter by tag prefix and skip pre-releases explicitly —
  # the repo-wide "latest" pointer is not reliable here.
  step "Resolving latest release..."
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=100" | \
    awk '
      /"tag_name":.*"obsigna\/v/ {
        match($0, /"obsigna\/v[^"]+/)
        tag = substr($0, RSTART + 10, RLENGTH - 10)
      }
      tag != "" && /"prerelease": false/ { print tag; exit }
      /"prerelease": true/ { tag = "" }
    ')
  [ -n "$VERSION" ] || die "Could not resolve latest stable obsigna version from GitHub API"
  echo "    version: ${VERSION}"

  # Download
  ARCHIVE="obsigna_${VERSION}_linux_${GOARCH}.tar.gz"
  # %2F-encode the slash in the tag so the URL matches the canonical form used
  # by the Homebrew formula (daemon/.goreleaser.yaml url_template).
  RELEASE_BASE="https://github.com/${REPO}/releases/download/obsigna%2Fv${VERSION}"

  step "Downloading ${ARCHIVE}..."
  WORK_DIR=$(mktemp -d)
  curl -fsSL -o "${WORK_DIR}/${ARCHIVE}" "${RELEASE_BASE}/${ARCHIVE}"

  # Verify checksum before writing anything to the filesystem.
  # This is a cryptographic signing daemon — supply chain integrity matters.
  step "Verifying checksum..."
  curl -fsSL -o "${WORK_DIR}/checksums.txt" "${RELEASE_BASE}/checksums.txt"
  EXPECTED=$(awk -v f="${ARCHIVE}" '$2 == f { print $1 }' "${WORK_DIR}/checksums.txt")
  [ -n "$EXPECTED" ] || die "No checksum entry found for ${ARCHIVE} in checksums.txt"
  ACTUAL=$(sha256sum "${WORK_DIR}/${ARCHIVE}" | awk '{print $1}')
  [ "$ACTUAL" = "$EXPECTED" ] || \
    die "Checksum mismatch for ${ARCHIVE} — download may be corrupted or tampered with"
  echo "    OK: ${EXPECTED}"

  # Install binaries
  step "Installing binaries to ${INSTALL_DIR}..."
  mkdir -p "$INSTALL_DIR"
  mkdir -p "${WORK_DIR}/extract"
  # GoReleaser archives are flat: obsigna-daemon, obsigna, and agent-receipts sit
  # at the archive root (no wrapping directory), matching how the release
  # attestation gate and scripts/daemon_protocol/check.py extract them.
  tar -xzf "${WORK_DIR}/${ARCHIVE}" -C "${WORK_DIR}/extract"

  # Smoke-test the extracted binary BEFORE overwriting any installed version.
  # If the new binary is incompatible (glibc mismatch, bad arch) the existing
  # install is preserved and the script aborts cleanly.
  "${WORK_DIR}/extract/obsigna-daemon" --version >/dev/null 2>&1 || \
    die "New binary failed to run on this host — aborting to preserve existing install"

  install -m 0755 "${WORK_DIR}/extract/obsigna-daemon" "${INSTALL_DIR}/"
  install -m 0755 "${WORK_DIR}/extract/agent-receipts"        "${INSTALL_DIR}/"

  # Key init — attempt unconditionally and handle both outcomes.
  # When -init succeeds the key is at KEY_FILE (the XDG default).
  # When -init fails: if KEY_FILE exists, treat it as "already present" (common
  # on re-runs). Otherwise warn — the key may exist at a custom AGENTRECEIPTS_KEY
  # or XDG_DATA_HOME path and the user should verify it before proceeding.
  step "Generating signing key..."
  if "${INSTALL_DIR}/obsigna-daemon" -init 2>"${WORK_DIR}/init.err"; then
    echo "    key: ${KEY_FILE}"
  elif [ -f "$KEY_FILE" ]; then
    echo "    signing key already present — skipping"
  else
    printf '    Warning: -init reported: %s\n' "$(head -1 "${WORK_DIR}/init.err")"
    printf '    If AGENTRECEIPTS_KEY or XDG_DATA_HOME is set, verify the key exists\n'
    printf '    at the custom path before starting the service.\n'
  fi

  # Install systemd user unit.
  # The embedded unit is kept in sync with daemon/packaging/linux/agent-receipts-daemon.service.
  # Always written on install/upgrade — if you have custom Environment= settings, put them
  # in a drop-in file instead: ~/.config/systemd/user/agent-receipts-daemon.service.d/override.conf
  step "Installing systemd user unit to ${UNIT_DIR}..."
  mkdir -p "$UNIT_DIR"
  cat > "${UNIT_DIR}/${UNIT_NAME}" << 'UNIT_EOF'
[Unit]
Description=Agent Receipts signing daemon
Documentation=https://github.com/agent-receipts/ar/tree/main/daemon

[Service]
Type=simple
# %h is the user's home directory; %t expands to $XDG_RUNTIME_DIR, ensuring the
# socket path is correct even when the service starts outside a PAM session.
# If ExecStart is changed to a different binary location, update ExecStartPre too.
#
# Key is generated only on a truly fresh install (no receipts.db). If the key is
# missing but a database exists, the service fails loudly for operator recovery
# rather than silently creating a new signing identity (see daemon/daemon.go:148-151).
ExecStartPre=/bin/sh -c '\
  if test -f "%h/.local/share/agent-receipts/signing.key"; then exit 0;\
  elif test -f "%h/.local/share/agent-receipts/receipts.db"; then\
    printf "signing key missing but receipts.db exists -- recover the key before restarting\n" >&2; exit 1;\
  else exec "%h/.local/bin/obsigna-daemon" -init; fi'
ExecStart=%h/.local/bin/obsigna-daemon \
  -socket %t/agentreceipts/events.sock
Restart=on-failure
RestartSec=5s

# Ensure %t/agentreceipts/ exists before the socket bind.
RuntimeDirectory=agentreceipts
RuntimeDirectoryMode=0700

[Install]
WantedBy=default.target
UNIT_EOF

  # Enable and start (or restart on upgrade).
  # systemctl --user needs an active user session. Pre-set XDG_RUNTIME_DIR so
  # installs over SSH without linger still attempt the enable step.
  step "Enabling agent-receipts-daemon..."
  XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  export XDG_RUNTIME_DIR
  SYSTEMCTL_ERR="${WORK_DIR}/systemctl.err"
  if systemctl --user daemon-reload 2>"$SYSTEMCTL_ERR"; then
    # enable marks the unit for auto-start; restart starts or restarts the running
    # process so upgrades take effect without a separate manual restart step.
    if systemctl --user enable agent-receipts-daemon 2>>"$SYSTEMCTL_ERR" && \
       systemctl --user restart agent-receipts-daemon 2>>"$SYSTEMCTL_ERR"; then
      STARTED=1
      echo "    Service running."
    else
      printf '    Service failed to start.\n'
      printf '    Diagnose with:\n'
      printf '      systemctl --user status agent-receipts-daemon\n'
      printf '      journalctl --user -u agent-receipts-daemon -n 20\n'
      if [ -s "$SYSTEMCTL_ERR" ]; then
        printf '    systemctl error: %s\n' "$(head -1 "$SYSTEMCTL_ERR")"
      fi
      exit 1
    fi
  else
    printf '    No active systemd user session'
    if [ -s "$SYSTEMCTL_ERR" ]; then
      printf ' (%s)' "$(head -1 "$SYSTEMCTL_ERR")"
    fi
    printf '.\n'
    printf '    After enabling linger (see below) and logging back in, run:\n'
    printf '      systemctl --user daemon-reload\n'
    printf '      systemctl --user enable --now agent-receipts-daemon\n'
  fi

  # Add XDG_RUNTIME_DIR export to ~/.bashrc so SSH sessions have it set.
  # Only edits the file if it already exists (non-bash users: add manually
  # to your shell rc file). Uses a marker comment for idempotency.
  if [ ! -f "$BASHRC" ]; then
    echo "    ~/.bashrc not found — skipping (add manually to your shell rc file if needed)"
  elif grep -qF '# agent-receipts: XDG_RUNTIME_DIR' "$BASHRC" || \
       grep -qE '^[[:space:]]*export[[:space:]]+XDG_RUNTIME_DIR' "$BASHRC"; then
    echo "    XDG_RUNTIME_DIR already in ${BASHRC} — skipping"
  else
    step "Adding XDG_RUNTIME_DIR to ${BASHRC}..."
    printf '\n# agent-receipts: XDG_RUNTIME_DIR — needed for systemd user services in SSH sessions\n' >> "$BASHRC"
    # SC2016: $(id -u) must expand when .bashrc is sourced, not now.
    # shellcheck disable=SC2016
    printf 'export XDG_RUNTIME_DIR=/run/user/$(id -u)\n' >> "$BASHRC"
  fi

  # Warn if ~/.local/bin is not in PATH so binaries are findable right away.
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) printf '\nNote: %s is not in your PATH.\n' "$INSTALL_DIR"
       # SC2016: $PATH is literal text for the user to copy — must not expand here.
       # shellcheck disable=SC2016
       printf 'Add to your shell rc file:\n  export PATH="%s:$PATH"\n' "$INSTALL_DIR" ;;
  esac

  # Summary
  printf '\nagent-receipts-daemon v%s installed to %s.\n' "$VERSION" "$INSTALL_DIR"
  printf '\n'
  printf 'One root step required — enables the user session to persist across logouts:\n'
  printf '\n'
  printf '    sudo loginctl enable-linger %s\n' "$(id -un)"
  printf '\n'
  if [ "$STARTED" = "1" ]; then
    printf 'The service is running. Enable linger so it survives future logouts and\n'
    printf 'starts automatically on boot without requiring a login session.\n'
  else
    printf 'Without linger the user manager does not persist across logouts. After\n'
    printf 'enabling linger, log out and back in (or open a new SSH session).\n'
  fi
  printf '\n'
  printf 'Note: MCP emitters running as system services need this in their unit file:\n'
  printf '    Environment=XDG_RUNTIME_DIR=/run/user/<uid>\n'
  printf 'See: https://github.com/agent-receipts/ar/tree/main/daemon/packaging/linux\n'
}

main "$@"
