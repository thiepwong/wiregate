# Deploying the WireGate technical POC

This bundle targets Linux `amd64` and `arm64` gateways. It uses:

- A native agent running as `root` through systemd and a Unix socket.
- A web application running in Docker with a fixed UID/GID and all Linux
  capabilities dropped.
- Mandatory TLS, with no agent TCP listener.

## 1. Target host requirements

- Ubuntu or Debian with systemd and a WireGuard-capable kernel.
- Docker Engine and Docker Compose v2.
- `wireguard-tools`, `iproute2`, `nftables`, `openssl`, `getent`, `groupadd`,
  and `systemctl`.
- TCP port `8443` allowed from the management network.
- WireGuard UDP ports configured separately for each existing interface.
- No existing WireGate installation. The fresh-host installer refuses to
  overwrite existing WireGate state.

Check the target architecture:

```bash
uname -m
# x86_64  -> use the linux-amd64 bundle
# aarch64 -> use the linux-arm64 bundle
```

## 2. Copy and verify the bundle

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

The installer generates a self-signed certificate, builds the web image
offline from the binary in the bundle, starts the agent and web application,
waits for the health check, and prints a 15-minute bootstrap token.

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
characters. The token can be used once and expires after 15 minutes.

## 5. Verify

```bash
sudo systemctl status wiregate-agent.socket wiregate-agent.service
sudo journalctl -u wiregate-agent.service -n 100 --no-pager

sudo docker compose \
  --env-file /etc/wiregate-web/runtime.env \
  -f /etc/wiregate-web/compose.yaml ps

curl -k https://127.0.0.1:8443/healthz
curl -k https://127.0.0.1:8443/readyz

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
- The UI displays `wg-quick` interfaces found under `/etc/wireguard`.
- Do not select **Adopt interface** until you have reviewed its preview and
  warnings and verified a backup.

## 6. Required backups

Stop the web application and agent or use a consistent SQLite backup, then
protect these paths:

```text
/etc/wiregate/keys/
/etc/wiregate/agent.yaml
/var/lib/wiregate-agent/agent.db
/var/lib/wiregate-web/web.db
/etc/wiregate-web/tls/
/etc/wireguard/
```

Losing `/etc/wiregate/keys` makes stored secrets unrecoverable.

## 7. Uninstall

Preserve configuration, keys, databases, and tunnels:

```bash
sudo ./uninstall.sh
```

Removing metadata, keys, and databases requires explicit confirmation:

```bash
sudo ./uninstall.sh --purge --confirm-purge
```

The `purge` option does not remove `/etc/wireguard`; manage those tunnels
separately.

## 8. Upgrade an existing installation

Verify and extract the new bundle as described in section 2, then run:

```bash
cd /tmp/wiregate-<version>-linux-<arch>
sudo ./upgrade.sh
```

The upgrade builds the image before opening the maintenance window, then
briefly stops the web application and agent to create a consistent backup. The
backup contains the previous binary, databases, keys, TLS material, and
`/etc/wireguard`, and is stored under
`/var/backups/wiregate/upgrade-<timestamp>`.

An active `wg-quick` tunnel is not stopped; the agent and web application are
replaced independently of the data plane. After the upgrade, always verify
`readyz`, container health, and `wg-quick@<interface>.service`.

## 9. POC scope

This version includes discovery and adoption UI, IPAM import, existing peer
import with or without a preshared key, greenfield interface support, managed,
one-time, and external-key peer creation, peer updates, managed `.conf` and QR
exports, and disable, enable, and revoke lifecycle actions. These flows use an
operation journal and revision/hash guards and have passed an adopt-only smoke
test and reboot gate on Ubuntu ARM64.

Interface start/stop UI, drift resolution, operation rollback UI, and atomic
re-enrollment remain fail-closed. nftables coexistence with every firewall
manager and AWS-equivalent traffic remain integration gates before production.
