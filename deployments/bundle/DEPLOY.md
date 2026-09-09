# Deploying the WireGate technical POC

This bundle targets Linux `amd64` and `arm64` gateways. It uses:

- A native agent running as `root` through systemd and a Unix socket.
- A web application running as an unprivileged native systemd service by
  default, or in Docker with a fixed UID/GID and all Linux capabilities
  dropped.
- Mandatory TLS, with no agent TCP listener.

## 1. Target host requirements

- Ubuntu or Debian with systemd and a WireGuard-capable kernel.
- APT access when `wireguard-tools`, `iproute2`, `nftables`, `openssl`, or
  `util-linux` need to be installed automatically.
- Docker Engine and Docker Compose v2 only for `--web-runtime docker`.
- Standard account management utilities, `runuser`, and `systemctl`.
- TCP port `8443` allowed from the management network.
- WireGuard UDP ports configured separately for each interface.
- No existing WireGate installation. The fresh-host installer refuses to
  overwrite existing WireGate state.

Check the target architecture:

```bash
uname -m
# x86_64  -> use the linux-amd64 bundle
# aarch64 -> use the linux-arm64 bundle
```

## 2. Copy and verify the bundle

Download the matching release directly on the target host:

```bash
VERSION=0.4.2-poc
ARCH=amd64 # use arm64 for aarch64 hosts
RELEASE_URL="https://github.com/thiepwong/wiregate/releases/download/v${VERSION}"
curl -fLO "${RELEASE_URL}/wiregate-${VERSION}-linux-${ARCH}.tar.gz"
curl -fLO "${RELEASE_URL}/wiregate-${VERSION}-linux-${ARCH}.tar.gz.sha256"
sha256sum -c "wiregate-${VERSION}-linux-${ARCH}.tar.gz.sha256"
tar -xzf "wiregate-${VERSION}-linux-${ARCH}.tar.gz"
cd "wiregate-${VERSION}-linux-${ARCH}"
sha256sum -c SHA256SUMS
```

Or copy a locally built bundle:

```bash
scp wiregate-*-linux-amd64.tar.gz user@gateway:/tmp/
scp wiregate-*-linux-amd64.tar.gz.sha256 user@gateway:/tmp/
ssh user@gateway
cd /tmp
sha256sum -c wiregate-*-linux-amd64.tar.gz.sha256
tar -xzf wiregate-*-linux-amd64.tar.gz
cd wiregate-*-linux-amd64
sha256sum -c SHA256SUMS
```

## 3. Install

The native systemd web runtime is the default and does not require Docker.
When WireGuard or its host networking tools are missing, the installer uses
APT to install `wireguard-tools`, `iproute2`, `nftables`, `openssl`, and the
native runtime utility from `util-linux` before starting WireGate.

With an existing certificate:

```bash
sudo ./install.sh \
  --public-host vpn-admin.example.com \
  --tls-cert /path/fullchain.pem \
  --tls-key /path/privkey.pem
```

For a lab or LAN without a certificate:

```bash
sudo ./install.sh --public-host 192.168.1.10
```

To use the Docker web runtime instead:

```bash
sudo ./install.sh \
  --web-runtime docker \
  --public-host 192.168.1.10
```

The installer generates a self-signed certificate when needed, starts the
agent and selected web runtime, waits for its health check, and prints a
15-minute bootstrap token. Docker mode builds the web image offline from the
binary in the bundle.

If UID/GID `10001` is already in use, select an unused pair:

```bash
sudo ./install.sh \
  --public-host 192.168.1.10 \
  --web-uid 12001 \
  --web-gid 12001
```

## 4. Create the first administrator

Open the URL printed by the installer. Expand **First-time setup**, then enter
the bootstrap token, a username, a display name, and a password of at least 12
characters. The token can be used once, expires after 15 minutes, and is
permanently disabled after the first administrator is created.

Passwords are hashed with Argon2id. Five failed sign-in attempts lock the
account for 15 minutes; sessions have a 12-hour absolute lifetime and a
30-minute idle lifetime. Session cookies are `Secure`, `HttpOnly`, and
`SameSite=Strict`; state-changing requests also require a same-origin CSRF
token, and sensitive operations require recent password confirmation.

## 5. Restrict or disable web access after setup

The default broad bind address makes initial remote setup easy, but it should
not remain exposed to the Internet. After creating and starting the WireGuard
interface, find its tunnel address and bind the administration interface only
to that address:

```bash
sudo wg show interfaces
ip -o address show dev wg0
sudo wiregate-web-access restrict --bind-address 10.77.0.1
sudo wiregate-web-access status
```

`restrict` accepts only loopback or an address assigned to an active WireGuard
interface. It safely updates either runtime, verifies health, and restores the
previous binding if the change fails. Use `127.0.0.1` instead when the web UI
will be reached only through an SSH tunnel:

```bash
sudo wiregate-web-access restrict --bind-address 127.0.0.1
ssh -L 8443:127.0.0.1:8443 user@gateway
```

To remove the web attack surface completely while leaving the WireGate agent
and all tunnels running:

```bash
sudo wiregate-web-access disable

# Restore it later from a root/SSH session:
sudo wiregate-web-access enable
```

The access state is persisted under `/etc/wiregate-web` and an upgrade does
not re-enable a disabled web application. Network restriction is intentionally
a root-only host operation; the web UI cannot grant itself more exposure.

## 6. Recover a forgotten administrator password

Run recovery from an interactive root or SSH terminal:

```bash
sudo wiregate-admin reset-password --username admin
```

The password is entered twice without terminal echo and must contain at least
12 characters. The command temporarily stops an enabled native or Docker web
runtime so login cannot race the reset transaction. It then unlocks the admin,
revokes all existing sessions, records an audit event, and restores the prior
web access state. If web access was already disabled, it stays disabled.

## 7. Verify

```bash
sudo systemctl status wiregate-agent.socket wiregate-agent.service
sudo journalctl -u wiregate-agent.service -n 100 --no-pager

# Native runtime:
sudo systemctl status wiregate-web.service
sudo journalctl -u wiregate-web.service -n 100 --no-pager

# Docker runtime:
sudo docker compose \
  --env-file /etc/wiregate-web/runtime.env \
  -f /etc/wiregate-web/compose.yaml ps

curl -k https://127.0.0.1:8443/healthz
curl -k https://127.0.0.1:8443/readyz
sudo wiregate-web-access status

sudo stat -c '%a %U:%G %n' \
  /etc/wiregate/keys \
  /etc/wiregate/keys/key-v0001.bin \
  /var/lib/wiregate-agent/agent.db \
  /var/lib/wiregate-web/web.db
```

Expected results:

- `healthz` and `readyz` return HTTP 200.
- The agent and web application are active and healthy.
- The key directory has mode `700`; the key and agent database have mode
  `600`.
- The UI displays existing `wg-quick` interfaces and can create a new one on a
  host without an existing configuration.
- Do not select **Adopt interface** until you have reviewed its preview and
  warnings and verified a backup.

After restricting the native runtime to a WireGuard address, run the HTTP
probes against that address instead of `127.0.0.1`. When web access is disabled,
`wiregate-web-access status` should report it unavailable while the agent and
`wg-quick@<interface>.service` remain active.

## 8. Required backups

Stop the web application and agent or use a consistent SQLite backup, then
protect these paths:

```text
/etc/wiregate/keys/
/etc/wiregate/agent.yaml
/var/lib/wiregate-agent/agent.db
/var/lib/wiregate-web/web.db
/etc/wiregate-web/
/etc/wireguard/
```

Losing `/etc/wiregate/keys` makes stored secrets unrecoverable.

## 9. Uninstall

Preserve configuration, keys, databases, and tunnels:

```bash
sudo ./uninstall.sh
```

Removing metadata, keys, and databases requires explicit confirmation:

```bash
sudo ./uninstall.sh --purge --confirm-purge
```

The `purge` option does not remove `/etc/wireguard` or packages installed by
APT; manage the tunnels and host packages separately.

## 10. Upgrade an existing installation

Verify and extract the new bundle as described in section 2, then run:

```bash
cd /tmp/wiregate-<version>-linux-<arch>
sudo ./upgrade.sh
```

The upgrade detects the recorded web runtime. Docker mode builds the image
before opening the maintenance window; native mode replaces the web binary and
systemd unit. It briefly stops the web application and agent to create a
consistent backup containing the previous binaries, databases, keys, TLS
material, and `/etc/wireguard`, stored under
`/var/backups/wiregate/upgrade-<timestamp>`.

An active `wg-quick` tunnel is not stopped; the agent and web application are
replaced independently of the data plane. After the upgrade, always verify
the selected web runtime, its persisted access state, and
`wg-quick@<interface>.service`. Verify `readyz` only when web access is enabled.

## 11. POC scope

This version includes discovery and adoption UI, IPAM import, existing peer
import with or without a preshared key, greenfield interface support, managed,
one-time, and external-key peer creation, peer updates, managed `.conf` and QR
exports, and disable, enable, and revoke lifecycle actions. These flows use an
operation journal and revision/hash guards and have passed an adopt-only smoke
test and reboot gate on Ubuntu ARM64.

Interface start/stop UI, drift resolution, operation rollback UI, and atomic
re-enrollment remain fail-closed. nftables coexistence with every firewall
manager and AWS-equivalent traffic remain integration gates before production.
