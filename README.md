# WireGate

WireGate is a self-hosted control plane for an existing WireGuard gateway. It
runs a privileged native agent on Linux and an unprivileged web application in
Docker. The current phase is adopt-only: WireGate discovers an existing
`wg-quick` interface, previews the import, adopts it without rewriting its
configuration file, and then manages both imported and newly created peers.

> WireGate is currently a technical POC. Use it in a test environment first,
> keep a verified backup of `/etc/wireguard`, and review the remaining
> production gates in [`docs/README.md`](docs/README.md).

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
- Docker Engine with Docker Compose v2.
- `wireguard-tools`, `iproute2`, `nftables`, `openssl`, and standard account
  management utilities.
- An existing `wg-quick` configuration under `/etc/wireguard` for the
  adopt-only workflow.
- TCP port `8443` reachable from the management network. WireGuard UDP ports
  remain independent of the WireGate web port.

## Clone the repository

```bash
git clone <repository-url> wiregate
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
WireGuard interfaces. Use a Linux host or the Multipass lab described in
[`docs/MULTIPASS_LAB_VI.md`](docs/MULTIPASS_LAB_VI.md) for end-to-end testing.

## Build Linux release bundles

Build self-contained bundles for Linux `amd64` and `arm64`:

```bash
WIREGATE_VERSION=0.3.0-poc GOTOOLCHAIN=auto make -C src bundle
```

The build writes archives and checksum files to `build/releases/`:

```text
wiregate-0.3.0-poc-linux-amd64.tar.gz
wiregate-0.3.0-poc-linux-amd64.tar.gz.sha256
wiregate-0.3.0-poc-linux-arm64.tar.gz
wiregate-0.3.0-poc-linux-arm64.tar.gz.sha256
```

Build only one target architecture when needed:

```bash
cd src
WIREGATE_VERSION=0.3.0-poc GOTOOLCHAIN=auto ./scripts/build-bundle.sh amd64
```

## Install on a Linux WireGuard gateway

Choose the archive matching the target reported by `uname -m` (`x86_64` maps
to `amd64`; `aarch64` maps to `arm64`). Copy both the archive and its checksum
to the gateway, then verify and extract them:

```bash
scp build/releases/wiregate-0.3.0-poc-linux-amd64.tar.gz* user@gateway:/tmp/
ssh user@gateway
cd /tmp
sha256sum -c wiregate-0.3.0-poc-linux-amd64.tar.gz.sha256
tar -xzf wiregate-0.3.0-poc-linux-amd64.tar.gz
cd wiregate-0.3.0-poc-linux-amd64
sha256sum -c SHA256SUMS
```

Install with an existing TLS certificate:

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

The installer performs these actions:

1. Installs the native agent as a root-owned systemd service and Unix socket.
2. Builds the web image from the bundle without pulling an application image.
3. Starts the unprivileged web container with all Linux capabilities dropped.
4. Waits for readiness and prints the HTTPS URL and a one-time bootstrap token
   that is valid for 15 minutes.

Open the printed URL, expand **First-time setup**, and create the first
administrator with the bootstrap token and a password of at least 12
characters.

## Adopt the existing WireGuard interface

After signing in:

1. Confirm that the existing interface and its peers appear in the inventory.
2. Select **Adopt interface** and review the redacted preview and warnings.
3. Commit the operation. Adoption imports peer metadata and IPAM allocations
   without rewriting the existing WireGuard configuration file.
4. Use **Add peer** to create a managed, one-time, or external-key peer. Existing
   adopted peers can be edited, disabled, enabled, or revoked.

Back up `/etc/wireguard`, `/etc/wiregate/keys`, and both WireGate databases
before adopting or changing peers. Losing `/etc/wiregate/keys` makes stored
secrets unrecoverable.

## Verify the deployment

```bash
sudo systemctl status wiregate-agent.socket wiregate-agent.service
sudo docker compose \
  --env-file /etc/wiregate-web/runtime.env \
  -f /etc/wiregate-web/compose.yaml ps
curl -k https://127.0.0.1:8443/healthz
curl -k https://127.0.0.1:8443/readyz
sudo wg show
```

Both HTTP probes should return status `200`, the systemd agent should be
active, and the web container should be healthy. The existing WireGuard tunnel
must remain active throughout adoption.

For backup, uninstall, and upgrade procedures, see
[`deployments/bundle/DEPLOY.md`](deployments/bundle/DEPLOY.md).

## Further documentation

- [`docs/00_START_HERE.md`](docs/00_START_HERE.md): documentation entry point.
- [`docs/ADOPT_ONLY_PHASE_VI.md`](docs/ADOPT_ONLY_PHASE_VI.md): adopt-only phase
  analysis and acceptance evidence.
- [`docs/WIREGATE_SOLUTION.md`](docs/WIREGATE_SOLUTION.md): solution design.
- [`docs/MULTIPASS_LAB_VI.md`](docs/MULTIPASS_LAB_VI.md): macOS/Multipass test
  environment runbook.

## License

WireGate is released under the [MIT License](LICENSE).

Copyright (c) 2026 [Thiep Wong](mailto:thiep.wong@gmail.com).
