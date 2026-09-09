#!/bin/sh

# File: deployments/bundle/install.sh
# Project: WireGate
# Copyright (c) 2026 Thiep Wong
# SPDX-License-Identifier: MIT
# Author: Thiep Wong
# Email: thiep.wong@gmail.com
# Date: 2026-08-24
# Description: WireGate build or deployment script.

set -eu

WEB_UID=10001
WEB_GID=10001
WEB_PORT=8443
WEB_RUNTIME=native
BIND_ADDRESS=0.0.0.0
PUBLIC_HOST=
TLS_CERT=
TLS_KEY=

usage() {
  printf '%s\n' \
    "Usage: sudo ./install.sh --public-host <DNS-or-IP> [options]" \
    "" \
    "Options:" \
    "  --tls-cert <path>       Existing PEM certificate" \
    "  --tls-key <path>        Existing PEM private key" \
    "  --web-runtime <mode>    native or docker (default: native)" \
    "  --web-uid <number>      Fixed web UID (default: 10001)" \
    "  --web-gid <number>      Fixed web/socket GID (default: 10001)" \
    "  --web-port <number>     HTTPS port (default: 8443)" \
    "  --bind-address <IP>     Host bind address (default: 0.0.0.0)" \
    "  --help                  Show this help"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --public-host)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      PUBLIC_HOST=$2
      shift 2
      ;;
    --tls-cert)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      TLS_CERT=$2
      shift 2
      ;;
    --tls-key)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      TLS_KEY=$2
      shift 2
      ;;
    --web-runtime)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      WEB_RUNTIME=$2
      shift 2
      ;;
    --web-uid)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      WEB_UID=$2
      shift 2
      ;;
    --web-gid)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      WEB_GID=$2
      shift 2
      ;;
    --web-port)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      WEB_PORT=$2
      shift 2
      ;;
    --bind-address)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      BIND_ADDRESS=$2
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[ "$(id -u)" -eq 0 ] || {
  printf '%s\n' "install.sh must run as root" >&2
  exit 1
}
[ -n "$PUBLIC_HOST" ] || {
  printf '%s\n' "--public-host is required" >&2
  exit 2
}
case "$WEB_RUNTIME" in
  native|docker) ;;
  *)
    printf '%s\n' "--web-runtime must be native or docker" >&2
    exit 2
    ;;
esac
case "$PUBLIC_HOST" in
  *[!A-Za-z0-9_.:-]*)
    printf '%s\n' "public host contains unsupported characters" >&2
    exit 2
    ;;
esac
case "$WEB_UID:$WEB_GID:$WEB_PORT" in
  *[!0-9:]*)
    printf '%s\n' "UID, GID and port must be numeric" >&2
    exit 2
    ;;
esac
case "$BIND_ADDRESS" in
  *[!0-9A-Fa-f:.]*)
    printf '%s\n' "bind address must be an IPv4 or IPv6 literal" >&2
    exit 2
    ;;
esac
[ -n "$BIND_ADDRESS" ] || {
  printf '%s\n' "bind address must not be empty" >&2
  exit 2
}
[ "$WEB_UID" -gt 0 ] && [ "$WEB_GID" -gt 0 ] || {
  printf '%s\n' "web UID/GID must be positive" >&2
  exit 2
}
[ "$WEB_PORT" -gt 0 ] && [ "$WEB_PORT" -le 65535 ] || {
  printf '%s\n' "web port must be between 1 and 65535" >&2
  exit 2
}
if [ "$WEB_RUNTIME" = native ] && [ "$WEB_PORT" -lt 1024 ]; then
  printf '%s\n' "native web runtime requires a non-privileged port (1024 or greater)" >&2
  exit 2
fi
if [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
  [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ] || {
    printf '%s\n' "--tls-cert and --tls-key must be supplied together" >&2
    exit 2
  }
  [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ] || {
    printf '%s\n' "TLS certificate/key must be regular files" >&2
    exit 2
  }
fi

[ -d /run/systemd/system ] || {
  printf '%s\n' "A systemd-based Linux host is required" >&2
  exit 1
}

for command_name in awk uname; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Required command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for required_path in \
  "$SCRIPT_DIR/ARCH" \
  "$SCRIPT_DIR/VERSION" \
  "$SCRIPT_DIR/admin.sh" \
  "$SCRIPT_DIR/web-access.sh" \
  "$SCRIPT_DIR/bin/wiregate-agent" \
  "$SCRIPT_DIR/bin/wiregate-web" \
  "$SCRIPT_DIR/web-image/Dockerfile" \
  "$SCRIPT_DIR/web-image/wiregate-web" \
  "$SCRIPT_DIR/systemd/wiregate-agent.service" \
  "$SCRIPT_DIR/systemd/wiregate-agent.socket" \
  "$SCRIPT_DIR/systemd/wiregate-web.service" \
  "$SCRIPT_DIR/systemd/wiregate.conf" \
  "$SCRIPT_DIR/compose.yaml"; do
  [ -f "$required_path" ] || {
    printf 'Release bundle is incomplete: %s is missing\n' "$required_path" >&2
    exit 1
  }
done
BUNDLE_ARCH=$(awk 'NR == 1 { print; exit }' "$SCRIPT_DIR/ARCH")
case "$(uname -m)" in
  x86_64) HOST_ARCH=amd64 ;;
  aarch64|arm64) HOST_ARCH=arm64 ;;
  *)
    printf 'Unsupported host architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac
[ "$BUNDLE_ARCH" = "$HOST_ARCH" ] || {
  printf 'Bundle architecture %s does not match host %s\n' "$BUNDLE_ARCH" "$HOST_ARCH" >&2
  exit 1
}

if [ -e /etc/wiregate/agent.yaml ] ||
   [ -e /var/lib/wiregate-agent/agent.db ] ||
   [ -e /etc/wiregate/keys/key-v0001.bin ]; then
  printf '%s\n' \
    "Existing WireGate state was detected." \
    "This installer is intentionally fresh-host only and will not overwrite it." >&2
  exit 1
fi

set --
if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; then
  set -- "$@" wireguard-tools
fi
command -v ip >/dev/null 2>&1 || set -- "$@" iproute2
command -v nft >/dev/null 2>&1 || set -- "$@" nftables
command -v openssl >/dev/null 2>&1 || set -- "$@" openssl
if ! command -v runuser >/dev/null 2>&1; then
  set -- "$@" util-linux
fi
if [ "$#" -gt 0 ]; then
  [ -r /etc/os-release ] || {
    printf '%s\n' "Cannot identify the host OS to install WireGuard" >&2
    exit 1
  }
  OS_FAMILY=$(
    . /etc/os-release
    printf '%s %s\n' "${ID:-}" "${ID_LIKE:-}"
  )
  case "$OS_FAMILY" in
    *ubuntu*|*debian*) ;;
    *)
      printf 'Automatic WireGuard installation supports Ubuntu and Debian; detected: %s\n' "$OS_FAMILY" >&2
      exit 1
      ;;
  esac
  command -v apt-get >/dev/null 2>&1 || {
    printf '%s\n' "apt-get is required to install WireGuard automatically" >&2
    exit 1
  }
  printf 'Installing missing host packages:'
  printf ' %s' "$@"
  printf '\n'
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
fi

for command_name in systemctl systemd-tmpfiles openssl install getent groupadd useradd nologin awk uname wg wg-quick ip nft; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Required command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done
command -v runuser >/dev/null 2>&1 || {
  printf '%s\n' "Required command is missing: runuser" >&2
  exit 1
}
if [ "$WEB_RUNTIME" = docker ]; then
  command -v docker >/dev/null 2>&1 || {
    printf '%s\n' "Docker is required when --web-runtime docker is selected" >&2
    exit 1
  }
  docker compose version >/dev/null 2>&1 || {
    printf '%s\n' "Docker Compose v2 is required" >&2
    exit 1
  }
  docker info >/dev/null 2>&1 || {
    printf '%s\n' "Docker daemon is unavailable" >&2
    exit 1
  }
fi

GROUP_BY_NAME=$(getent group wiregate || true)
GROUP_BY_GID=$(getent group "$WEB_GID" || true)
if [ -n "$GROUP_BY_NAME" ]; then
  EXISTING_GID=$(printf '%s\n' "$GROUP_BY_NAME" | awk -F: '{print $3}')
  [ "$EXISTING_GID" = "$WEB_GID" ] || {
    printf 'Group wiregate already uses GID %s, requested %s\n' "$EXISTING_GID" "$WEB_GID" >&2
    exit 1
  }
elif [ -n "$GROUP_BY_GID" ]; then
  printf 'Requested GID %s is already used by group %s\n' \
    "$WEB_GID" "$(printf '%s\n' "$GROUP_BY_GID" | awk -F: '{print $1}')" >&2
  exit 1
else
  groupadd --system --gid "$WEB_GID" wiregate
fi

USER_BY_NAME=$(getent passwd wiregate-web || true)
USER_BY_UID=$(getent passwd "$WEB_UID" || true)
if [ -n "$USER_BY_NAME" ]; then
  EXISTING_UID=$(printf '%s\n' "$USER_BY_NAME" | awk -F: '{print $3}')
  EXISTING_USER_GID=$(printf '%s\n' "$USER_BY_NAME" | awk -F: '{print $4}')
  [ "$EXISTING_UID" = "$WEB_UID" ] && [ "$EXISTING_USER_GID" = "$WEB_GID" ] || {
    printf '%s\n' "User wiregate-web exists with a different UID/GID" >&2
    exit 1
  }
elif [ -n "$USER_BY_UID" ]; then
  printf 'Requested UID %s is already used by user %s\n' \
    "$WEB_UID" "$(printf '%s\n' "$USER_BY_UID" | awk -F: '{print $1}')" >&2
  exit 1
else
  useradd --system --uid "$WEB_UID" --gid wiregate \
    --home-dir /nonexistent --no-create-home \
    --shell "$(command -v nologin)" wiregate-web
fi

install -d -m 0755 /usr/lib/wiregate
install -d -m 0700 /etc/wiregate /etc/wiregate/keys /var/lib/wiregate-agent
install -d -m 0755 /etc/wireguard
install -d -m 0750 -o "$WEB_UID" -g "$WEB_GID" /etc/wiregate-web
install -d -m 0700 -o "$WEB_UID" -g "$WEB_GID" /var/lib/wiregate-web
install -d -m 0750 -o "$WEB_UID" -g "$WEB_GID" /etc/wiregate-web/tls
install -m 0755 "$SCRIPT_DIR/bin/wiregate-agent" /usr/lib/wiregate/wiregate-agent
install -m 0755 "$SCRIPT_DIR/bin/wiregate-web" /usr/lib/wiregate/wiregate-web
install -m 0755 "$SCRIPT_DIR/admin.sh" /usr/sbin/wiregate-admin
install -m 0755 "$SCRIPT_DIR/web-access.sh" /usr/sbin/wiregate-web-access
install -m 0644 "$SCRIPT_DIR/systemd/wiregate-agent.service" /etc/systemd/system/wiregate-agent.service
install -m 0644 "$SCRIPT_DIR/systemd/wiregate-agent.socket" /etc/systemd/system/wiregate-agent.socket
install -m 0644 "$SCRIPT_DIR/systemd/wiregate.conf" /usr/lib/tmpfiles.d/wiregate.conf
install -m 0644 "$SCRIPT_DIR/compose.yaml" /etc/wiregate-web/compose.yaml
if [ "$WEB_RUNTIME" = native ]; then
  install -m 0644 "$SCRIPT_DIR/systemd/wiregate-web.service" /etc/systemd/system/wiregate-web.service
fi
printf '%s\n' "$WEB_RUNTIME" > /etc/wiregate-web/runtime.mode
chown root:root /etc/wiregate-web/runtime.mode
chmod 0600 /etc/wiregate-web/runtime.mode
printf '%s\n' "enabled" > /etc/wiregate-web/access.state
chown root:root /etc/wiregate-web/access.state
chmod 0600 /etc/wiregate-web/access.state

GATEWAY_ID=$(/usr/lib/wiregate/wiregate-agent init -key-dir /etc/wiregate/keys)
case "$GATEWAY_ID" in
  ????????-????-7???-[89ab]???-????????????) ;;
  *)
    printf 'Agent returned an invalid gateway ID: %s\n' "$GATEWAY_ID" >&2
    exit 1
    ;;
esac

umask 077
{
  printf 'gateway_id: "%s"\n' "$GATEWAY_ID"
  printf 'socket_path: "/run/wiregate/agent.sock"\n'
  printf 'database_path: "/var/lib/wiregate-agent/agent.db"\n'
  printf 'key_dir: "/etc/wiregate/keys"\n'
  printf 'wireguard_config_dir: "/etc/wireguard"\n'
  printf 'allowed_interfaces:\n'
  printf '  - "*"\n'
  printf 'allowed_peer_uid: %s\n' "$WEB_UID"
  printf 'allowed_peer_gid: %s\n' "$WEB_GID"
  printf 'runtime_poll_interval: 5s\n'
  printf 'file_scan_interval: 30s\n'
  printf 'operation_timeout: 30s\n'
  printf 'artifact_ttl: 10m\n'
  printf 'ip_quarantine_duration: 24h\n'
} > /etc/wiregate/agent.yaml
chmod 0600 /etc/wiregate/agent.yaml

if [ "$WEB_RUNTIME" = native ]; then
  case "$BIND_ADDRESS" in
    *:*) WEB_LISTEN_ADDRESS="[$BIND_ADDRESS]:$WEB_PORT" ;;
    *) WEB_LISTEN_ADDRESS="$BIND_ADDRESS:$WEB_PORT" ;;
  esac
else
  WEB_LISTEN_ADDRESS=0.0.0.0:8443
fi
{
  printf 'listen_address: "%s"\n' "$WEB_LISTEN_ADDRESS"
  printf 'agent_socket: "/run/wiregate/agent.sock"\n'
  printf 'database_path: "/var/lib/wiregate-web/web.db"\n'
  printf 'tls_cert_file: "/etc/wiregate-web/tls/tls.crt"\n'
  printf 'tls_key_file: "/etc/wiregate-web/tls/tls.key"\n'
} > /etc/wiregate-web/web.yaml
chown "$WEB_UID:$WEB_GID" /etc/wiregate-web/web.yaml
chmod 0640 /etc/wiregate-web/web.yaml

if [ -n "$TLS_CERT" ]; then
  install -o "$WEB_UID" -g "$WEB_GID" -m 0444 "$TLS_CERT" /etc/wiregate-web/tls/tls.crt
  install -o "$WEB_UID" -g "$WEB_GID" -m 0400 "$TLS_KEY" /etc/wiregate-web/tls/tls.key
else
  case "$PUBLIC_HOST" in
    *:*) SAN="IP:$PUBLIC_HOST" ;;
    *[!0-9.]*|*.*[A-Za-z]*|*[A-Za-z]*) SAN="DNS:$PUBLIC_HOST" ;;
    *) SAN="IP:$PUBLIC_HOST" ;;
  esac
  openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
    -subj "/CN=$PUBLIC_HOST" -addext "subjectAltName=$SAN" \
    -keyout /etc/wiregate-web/tls/tls.key \
    -out /etc/wiregate-web/tls/tls.crt >/dev/null 2>&1
  chown "$WEB_UID:$WEB_GID" /etc/wiregate-web/tls/tls.crt /etc/wiregate-web/tls/tls.key
  chmod 0444 /etc/wiregate-web/tls/tls.crt
  chmod 0400 /etc/wiregate-web/tls/tls.key
  printf '%s\n' "Generated a self-signed TLS certificate; replace it with a trusted certificate for production."
fi

systemd-tmpfiles --create /usr/lib/tmpfiles.d/wiregate.conf
systemctl daemon-reload
systemctl enable --now wiregate-agent.socket
systemctl enable --now wiregate-agent.service
systemctl is-active --quiet wiregate-agent.service || {
  systemctl status --no-pager wiregate-agent.service >&2 || true
  exit 1
}

if [ "$WEB_RUNTIME" = native ]; then
  systemctl enable --now wiregate-web.service
  attempt=0
  HEALTH=starting
  while [ "$attempt" -lt 30 ]; do
    if systemctl is-active --quiet wiregate-web.service &&
       runuser -u wiregate-web -- \
         /usr/lib/wiregate/wiregate-web healthcheck \
         -config /etc/wiregate-web/web.yaml >/dev/null 2>&1; then
      HEALTH=healthy
      break
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  [ "$HEALTH" = healthy ] || {
    systemctl status --no-pager wiregate-web.service >&2 || true
    printf 'wiregate-web native health status: %s\n' "$HEALTH" >&2
    exit 1
  }
  BOOTSTRAP_TOKEN=$(runuser -u wiregate-web -- \
    /usr/lib/wiregate/wiregate-web bootstrap-token \
    -config /etc/wiregate-web/web.yaml -ttl 15m)
else
  IMAGE_TAG="wiregate-web:$(awk 'NR == 1 { print; exit }' "$SCRIPT_DIR/VERSION")-$HOST_ARCH"
  docker build --pull=false -f "$SCRIPT_DIR/web-image/Dockerfile" \
    -t "$IMAGE_TAG" "$SCRIPT_DIR/web-image"
  IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE_TAG")
  case "$BIND_ADDRESS" in
    *:*) COMPOSE_BIND_ADDRESS="[$BIND_ADDRESS]" ;;
    *) COMPOSE_BIND_ADDRESS=$BIND_ADDRESS ;;
  esac
  {
    printf 'WIREGATE_WEB_IMAGE=%s\n' "$IMAGE_ID"
    printf 'WIREGATE_WEB_UID=%s\n' "$WEB_UID"
    printf 'WIREGATE_WEB_GID=%s\n' "$WEB_GID"
    printf 'WIREGATE_BIND_ADDRESS=%s\n' "$COMPOSE_BIND_ADDRESS"
    printf 'WIREGATE_WEB_PORT=%s\n' "$WEB_PORT"
  } > /etc/wiregate-web/runtime.env
  chown root:root /etc/wiregate-web/runtime.env
  chmod 0600 /etc/wiregate-web/runtime.env

  docker compose \
    --env-file /etc/wiregate-web/runtime.env \
    -f /etc/wiregate-web/compose.yaml up -d

  CONTAINER_ID=$(docker compose \
    --env-file /etc/wiregate-web/runtime.env \
    -f /etc/wiregate-web/compose.yaml ps -q wiregate-web)
  [ -n "$CONTAINER_ID" ] || {
    printf '%s\n' "wiregate-web container was not created" >&2
    exit 1
  }

  attempt=0
  HEALTH=starting
  while [ "$attempt" -lt 30 ]; do
    HEALTH=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER_ID")
    [ "$HEALTH" = healthy ] && break
    [ "$HEALTH" = unhealthy ] && break
    attempt=$((attempt + 1))
    sleep 2
  done
  [ "$HEALTH" = healthy ] || {
    docker compose \
      --env-file /etc/wiregate-web/runtime.env \
      -f /etc/wiregate-web/compose.yaml logs --no-color >&2 || true
    printf 'wiregate-web Docker health status: %s\n' "$HEALTH" >&2
    exit 1
  }

  BOOTSTRAP_TOKEN=$(docker compose \
    --env-file /etc/wiregate-web/runtime.env \
    -f /etc/wiregate-web/compose.yaml exec -T wiregate-web \
    /wiregate-web bootstrap-token -config /etc/wiregate/web.yaml -ttl 15m)
fi

case "$PUBLIC_HOST" in
  *:*) DISPLAY_HOST="[$PUBLIC_HOST]" ;;
  *) DISPLAY_HOST=$PUBLIC_HOST ;;
esac
printf '\n%s\n' "WireGate technical POC installed successfully."
printf 'Web runtime: %s\n' "$WEB_RUNTIME"
printf 'URL: https://%s:%s/\n' "$DISPLAY_HOST" "$WEB_PORT"
printf 'Bootstrap token (valid for 15 minutes): %s\n' "$BOOTSTRAP_TOKEN"
printf '%s\n' \
  "Complete the first-admin form immediately, then create or adopt the WireGuard interface." \
  "After setup, remove Internet exposure with one of these host commands:" \
  "  sudo wiregate-web-access restrict --bind-address <active-WireGuard-IP>" \
  "  sudo wiregate-web-access disable" \
  "Forgotten admin password: sudo wiregate-admin reset-password --username <admin>" \
  "Store a backup of /etc/wiregate/keys and both databases."
