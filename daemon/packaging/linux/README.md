# Linux systemd packaging for agent-receipts-daemon

Two unit files are provided:

| File | Target | Use case |
|------|--------|----------|
| `agent-receipts-daemon.service` | `~/.config/systemd/user/` | Per-user install — no root required |
| `agent-receipts-daemon.system.service` | `/etc/systemd/system/` | System-wide install with a dedicated service user |

---

## User-level install (recommended for beta)

Runs as the logged-in user. No root or dedicated system user needed. Data lives in the user's home directory.

### Quick install (Linux only)

```sh
curl -fsSL https://github.com/agent-receipts/obsigna/releases/latest/download/install.sh | sh
```

Handles binary download, key generation, unit install, and service start in one step. See [`daemon/install.sh`](../../install.sh) for details.

### Manual install

Use this path if you built from source or need a custom configuration.

#### Prerequisites

Install the binary (pick one):

```sh
# Build from source (go install @latest is not yet supported — see daemon/README.md):
git clone https://github.com/agent-receipts/obsigna
cd obsigna/daemon
go build -o ~/.local/bin/obsigna-daemon ./cmd/obsigna-daemon
```

The unit file assumes `~/.local/bin/obsigna-daemon` (`%h/.local/bin/…`). If the binary is elsewhere, edit `ExecStart` before installing the unit.

#### 1 — Generate the signing key (once, optional)

The unit's `ExecStartPre` generates the key automatically on first start if it
does not already exist, so this step is optional for most installs.

To generate it manually before enabling the service:

```sh
obsigna-daemon -init
```

This creates `~/.local/share/agent-receipts/signing.key` (0600) and
`~/.local/share/agent-receipts/signing.key.pub` (0644). Run `-init` only once — if
the key files already exist, `-init` fails with an error rather than overwrite them.
To rotate keys, remove the existing key files first, then re-run `-init` (this
invalidates the existing receipt chain).

> **Note:** the default key and database paths have recently moved to
> `~/.local/share/agent-receipts/` (XDG Base Directory). If you ran an earlier
> beta that wrote to `~/.agent-receipts/`, pass `-key` and `-db` flags or the
> corresponding environment variables to point the daemon at the old paths, or
> move the files to the new location.

#### 2 — Install and start the unit

```sh
mkdir -p ~/.config/systemd/user
cp agent-receipts-daemon.service ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable --now agent-receipts-daemon
```

#### 3 — Check status and logs

```sh
systemctl --user status agent-receipts-daemon
journalctl --user -u agent-receipts-daemon -f
```

#### Stopping / disabling

```sh
systemctl --user stop agent-receipts-daemon
systemctl --user disable agent-receipts-daemon
```

---

## System-level install (production)

Runs as a dedicated `agentreceipts` system user with restricted filesystem permissions and systemd sandboxing/hardening.

### Prerequisites

Install the binary to `/usr/local/bin/`:

```sh
# Build from source, then:
install -m 0755 obsigna-daemon /usr/local/bin/
```

### 1 — Create the `agentreceipts` user/group

**Option A — via systemd-sysusers (preferred on systemd distros):**

```sh
cp agent-receipts-daemon.system.sysusers /etc/sysusers.d/agent-receipts.conf
systemd-sysusers /etc/sysusers.d/agent-receipts.conf
```

> **Note:** `StateDirectory=agentreceipts` in the unit file causes systemd to create
> `/var/lib/agentreceipts` (owned by `agentreceipts`) on the first service start. If
> you use the sysusers approach, you do **not** need to create this directory manually.

**Option B — manually:**

```sh
useradd --system --no-create-home \
        --home-dir /var/lib/agentreceipts \
        --comment "Agent Receipts daemon" \
        --shell /usr/sbin/nologin \
        agentreceipts
```

### 2 — Generate the signing key (once)

The key must exist before the service first starts. Generate it as root and hand it to the service user:

```sh
# Create the config directory owned by root, group agentreceipts, mode 0750.
# Root can write into it (for key generation below); the service user can traverse
# but not create or unlink files. systemd does NOT manage this directory
# (no ConfigurationDirectory= in the unit) — the packaging step must create it.
install -d -m 0750 -o root -g agentreceipts /etc/agentreceipts

# Generate the key as root. /etc/agentreceipts is 0750 (root:agentreceipts): root
# can write into it; the service user can traverse but not create files.
# -public-key points the pub file to the writable StateDirectory so that
# /etc/agentreceipts can be mounted read-only by the service unit.
obsigna-daemon \
  -init \
  -key /etc/agentreceipts/signing.key \
  -public-key /var/lib/agentreceipts/signing.key.pub \
  -db /var/lib/agentreceipts/receipts.db

# Hand the private key to the service user (read-only).
chown agentreceipts:agentreceipts /etc/agentreceipts/signing.key
chmod 0400 /etc/agentreceipts/signing.key
```

The `-init` command writes `signing.key` (0600) and `signing.key.pub` (0644). After
the `chown`/`chmod` above, `signing.key` is owned by `agentreceipts` with mode 0400
(owner-read-only) — the daemon can read the key but cannot overwrite it. Runtime
immutability is reinforced by `ReadOnlyPaths=/etc/agentreceipts` in the unit, which
prevents writes even if the file permissions are later relaxed.

### 3 — Install and start the unit

```sh
cp agent-receipts-daemon.system.service /etc/systemd/system/agent-receipts-daemon.service

systemctl daemon-reload
systemctl enable --now agent-receipts-daemon
```

### 4 — Check status and logs

```sh
systemctl status agent-receipts-daemon
journalctl -u agent-receipts-daemon -f
```

### Stopping / disabling

```sh
systemctl stop agent-receipts-daemon
systemctl disable agent-receipts-daemon
```

---

## Socket path and emitter discovery

The daemon listens on a Unix-domain socket. Emitters (mcp-proxy, SDK consumers) connect to it to submit event frames.

| Install type | Default socket path |
|---|---|
| User-level | `$XDG_RUNTIME_DIR/agentreceipts/events.sock` (falls back to `/run/agentreceipts/events.sock`) |
| System-level | `/run/agentreceipts/events.sock` (set explicitly via `-socket`) |

Override at runtime:

```sh
# Daemon side:
obsigna-daemon -socket /custom/path/events.sock
# or:
AGENTRECEIPTS_SOCKET=/custom/path/events.sock obsigna-daemon

# Emitter side (mcp-proxy or SDK):
AGENTRECEIPTS_SOCKET=/custom/path/events.sock mcp-proxy ...
```

For the system-level unit, the socket lives under `/run/agentreceipts/` which `RuntimeDirectory=agentreceipts` creates (mode 0750, owned by `agentreceipts`). Emitter processes that need to connect must run as the `agentreceipts` user **or** be added to the `agentreceipts` group:

```sh
usermod -aG agentreceipts <emitter-user>
```

The socket itself is created with mode `0660` (owner `agentreceipts`, group `agentreceipts`), so group members can connect.

> **Note:** Members of the `agentreceipts` group also gain traversal access to
> `/var/lib/agentreceipts` (mode 0750) and read access to the receipt store at
> `/var/lib/agentreceipts/receipts.db` (mode 0640, group-readable). If that is
> undesirable, consider a dedicated socket group or set `SocketGroup=` in a
> `.socket` unit so that socket access and store access can be granted
> independently.

---

## Verifying the receipt chain

The `agent-receipts verify` CLI reads the SQLite store directly (read-only, safe to run while the daemon is running):

```sh
# User-level (uses default paths):
agent-receipts verify

# System-level (explicit paths):
agent-receipts verify \
  -db /var/lib/agentreceipts/receipts.db \
  -public-key /var/lib/agentreceipts/signing.key.pub \
  -chain-id default
```

Exit codes: `0` = verified, `1` = chain failed verification, `2` = usage error.
