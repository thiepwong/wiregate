# WireGate

WireGate is a self-hosted control plane for existing and new WireGuard
gateways. It runs a privileged native agent on Linux and an unprivileged web
application either as a native systemd service (the default) or in Docker.
WireGate can discover and adopt an existing `wg-quick` interface without
rewriting it, or create a new persistent interface and manage its peers.

> WireGate is currently a technical POC. Use it in a test environment first,
> keep a verified backup of `/etc/wireguard`, and complete the remaining
> integration and production-readiness gates before production use.

## Repository layout

```text
.
├── src/          # Go source, Protobuf APIs, migrations, examples, and build scripts
├── build/        # Generated binaries, caches, tools, and release bundles
├── deployments/  # Installer, Docker Compose definitions, Dockerfiles, and systemd units
└── docs/          # Architecture, design analysis, reviews, and test runbooks
```

Generated files under `build/` are ignored by Git except for `.gitkeep`.

## Prerequisites

For development and builds:

- Git and GNU Make.
- Go 1.26 or newer. With `GOTOOLCHAIN=auto`, Go can select the toolchain
  required by `src/go.mod`.
- [Buf CLI](https://buf.build/docs/installation/) for Protobuf linting and
  generation.
- Internet access on the first build to download Go modules and pinned
  Protobuf generators.

The web UI is embedded in the Go binary, so Node.js is not required.

For the Linux deployment target:

- Ubuntu or Debian with systemd and a WireGuard-capable kernel.
- The installer automatically installs `wireguard-tools`, `iproute2`,
  `nftables`, `openssl`, and `util-linux` with APT when required.
- Docker Engine with Docker Compose v2 only when the optional Docker web
  runtime is selected.
- An existing `wg-quick` configuration under `/etc/wireguard` is optional;
  the UI can create a new interface on a host without one.
- TCP port `8443` reachable from the management network. WireGuard UDP ports
  remain independent of the WireGate web port.

## Clone the repository

```bash
git clone https://github.com/thiepwong/wiregate.git
cd wiregate
```

If the repository has already been cloned, run all commands below from its
root directory.

## Check and build

Run the complete source check. This regenerates Protobuf code, formats Go
source, runs Buf lint, `go vet`, unit tests, and builds the host binaries:

```bash
GOTOOLCHAIN=auto make -C src check
```

The host binaries are written to:

```text
build/bin/wiregate-agent
build/bin/wiregate-web
```

The agent requires Linux networking APIs and root privileges. A binary built
on macOS is useful as a compile check, but it cannot manage the host's
WireGuard interfaces. Use a Linux host or a local Linux virtual machine for
end-to-end testing.

## Build Linux release bundles

Build self-contained bundles for Linux `amd64` and `arm64`:

```bash
WIREGATE_VERSION=0.4.3-poc GOTOOLCHAIN=auto make -C src bundle
```

The build writes archives and checksum files to `build/releases/`:

```text
wiregate-0.4.3-poc-linux-amd64.tar.gz
wiregate-0.4.3-poc-linux-amd64.tar.gz.sha256
wiregate-0.4.3-poc-linux-arm64.tar.gz
wiregate-0.4.3-poc-linux-arm64.tar.gz.sha256
```

Build only one target architecture when needed:

```bash
cd src
WIREGATE_VERSION=0.4.3-poc GOTOOLCHAIN=auto ./scripts/build-bundle.sh amd64
```

## Install on a Linux WireGuard gateway

Choose the archive matching the target reported by `uname -m` (`x86_64` maps
to `amd64`; `aarch64` maps to `arm64`). A target host can download the release
without cloning the repository:

```bash
VERSION=0.4.3-poc
ARCH=amd64 # use arm64 for aarch64 hosts
RELEASE_URL="https://github.com/thiepwong/wiregate/releases/download/v${VERSION}"
curl -fLO "${RELEASE_URL}/wiregate-${VERSION}-linux-${ARCH}.tar.gz"
curl -fLO "${RELEASE_URL}/wiregate-${VERSION}-linux-${ARCH}.tar.gz.sha256"
sha256sum -c "wiregate-${VERSION}-linux-${ARCH}.tar.gz.sha256"
tar -xzf "wiregate-${VERSION}-linux-${ARCH}.tar.gz"
cd "wiregate-${VERSION}-linux-${ARCH}"
sha256sum -c SHA256SUMS
```

Alternatively, copy both files from a local build, then verify and extract
them:

```bash
scp build/releases/wiregate-0.4.3-poc-linux-amd64.tar.gz* user@gateway:/tmp/
ssh user@gateway
cd /tmp
sha256sum -c wiregate-0.4.3-poc-linux-amd64.tar.gz.sha256
tar -xzf wiregate-0.4.3-poc-linux-amd64.tar.gz
cd wiregate-0.4.3-poc-linux-amd64
sha256sum -c SHA256SUMS
```

Install the default native systemd web runtime with an existing TLS
certificate:

```bash
sudo ./install.sh \
  --public-host vpn-admin.example.com \
  --tls-cert /path/to/fullchain.pem \
  --tls-key /path/to/privkey.pem
```

For an isolated lab, omit the certificate arguments to generate a self-signed
certificate:

```bash
sudo ./install.sh --public-host 192.168.1.10
```

Select the Docker web runtime explicitly when required:

```bash
sudo ./install.sh \
  --web-runtime docker \
  --public-host 192.168.1.10
```

The installer performs these actions:

1. Installs WireGuard and host runtime/networking tools with APT when needed.
2. Installs the native agent as a root-owned systemd service and Unix socket.
3. Starts the web application as an unprivileged native service by default, or
   builds and starts the hardened container when Docker is selected.
4. Waits for health and prints the HTTPS URL and a one-time bootstrap token
   that is valid for 15 minutes.

Open the printed URL, expand **First-time setup**, and create the first
administrator with the bootstrap token and a password of at least 12
characters. The token expires after 15 minutes and is permanently consumed by
the first successful administrator creation. Passwords use Argon2id, five
failed sign-ins cause a 15-minute lock, and authenticated mutations require a
secure session cookie plus same-origin CSRF protection.

## Create or adopt a WireGuard interface

After signing in:

1. On a new host, select **Create interface**, keep **Start automatically after
   reboot** enabled, review the preview, and commit it.
2. On an existing gateway, confirm its interfaces appear, select **Adopt
   interface**, review the redacted preview, and commit it. Adoption imports
   metadata without rewriting the existing configuration file.
3. Use **Add peer** to create a managed, one-time, or external-key peer.

The create form defaults to `10.200.0.1/24`: `10.200.0.0/24` is the VPN
network, the interface uses `.1`, and each peer receives one `/32` address
such as `10.200.0.2/32`.

For an interface created by WireGate, **Remove interface** stops and disables
its tunnel, removes its peers and profiles, and deletes only host files marked
as WireGate-owned. The action requires recent password confirmation and two
explicit confirmations. Observed or adopted host-owned interfaces cannot be
removed from WireGate.

Back up `/etc/wireguard`, `/etc/wiregate/keys`, and both WireGate databases
before adopting or changing peers. Losing `/etc/wiregate/keys` makes stored
secrets unrecoverable.

## Restrict the web administration interface

The broad bind address is intended only to make first-time setup simple. As
soon as the WireGuard interface is active, bind the web application only to
its tunnel address:

```bash
sudo wiregate-web-access restrict --bind-address 10.200.0.1
sudo wiregate-web-access status
```

The restriction command accepts only `127.0.0.1`, `::1`, or an address on an
active WireGuard interface. It updates and health-checks either the native or
Docker runtime and rolls back the change if the web application cannot start.

If web administration is not continuously required, disable it instead:

```bash
sudo wiregate-web-access disable
# Later, from an SSH/root session:
sudo wiregate-web-access enable
```

Disabling the web application does not stop the agent or any WireGuard tunnel.
The enabled/disabled state and restricted bind address are preserved across
WireGate upgrades.

## Recover a forgotten administrator password

Run the root-only recovery command from an interactive SSH or host terminal:

```bash
sudo wiregate-admin reset-password --username admin
```

The command hides password input, requires confirmation, temporarily stops an
enabled web runtime, unlocks the administrator, and revokes every existing web
session. A web runtime that was disabled before recovery remains disabled.

## Verify the deployment

```bash
sudo systemctl status wiregate-agent.socket wiregate-agent.service
sudo systemctl status wiregate-web.service # native runtime

# Docker runtime only:
sudo docker compose \
  --env-file /etc/wiregate-web/runtime.env \
  -f /etc/wiregate-web/compose.yaml ps
curl -k https://127.0.0.1:8443/healthz
curl -k https://127.0.0.1:8443/readyz
sudo wg show
```

Both HTTP probes should return status `200`. The agent and selected web runtime
should be active. A created interface with auto-start enabled must also report
active and enabled through `wg-quick@<interface>.service`.

For backup, uninstall, and upgrade procedures, see
[`deployments/bundle/DEPLOY.md`](deployments/bundle/DEPLOY.md).

## Documentation

The `docs/` directory is reserved for reviewed public documentation. Internal
design analysis and review notes are intentionally excluded from the public
repository.

## License

WireGate is released under the [MIT License](LICENSE).

Copyright (c) 2026 [Thiep Wong](mailto:thiep.wong@gmail.com).
