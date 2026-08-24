#!/bin/sh

# File: deployments/bundle/install.sh
# Project: WireGate
# Author: Thiep Wong
# Email: thiep.wong@gmail.com
# Date: 2026-08-24
# Description: WireGate build or deployment script.

set -eu

WEB_UID=10001
WEB_GID=10001
WEB_PORT=8443
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
    "  --web-uid <number>      Fixed container UID (default: 10001)" \
    "  --web-gid <number>      Fixed container GID/socket group (default: 10001)" \
    "  --web-port <number>     Published HTTPS port (default: 8443)" \
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
[ "$WEB_UID" -gt 0 ] && [ "$WEB_GID" -gt 0 ] || {
  printf '%s\n' "web UID/GID must be positive" >&2
  exit 2
}
[ "$WEB_PORT" -gt 0 ] && [ "$WEB_PORT" -le 65535 ] || {
  printf '%s\n' "web port must be between 1 and 65535" >&2
  exit 2
}
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

for command_name in systemctl systemd-tmpfiles docker openssl install getent groupadd useradd nologin awk uname wg wg-quick ip nft; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Required command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done
docker compose version >/dev/null 2>&1 || {
  printf '%s\n' "Docker Compose v2 is required" >&2
  exit 1
}
docker info >/dev/null 2>&1 || {
  printf '%s\n' "Docker daemon is unavailable" >&2
  exit 1
}
[ -d /run/systemd/system ] || {
  printf '%s\n' "A systemd-based Linux host is required" >&2
  exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
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
install -m 0644 "$SCRIPT_DIR/systemd/wiregate-agent.service" /etc/systemd/system/wiregate-agent.service
install -m 0644 "$SCRIPT_DIR/systemd/wiregate-agent.socket" /etc/systemd/system/wiregate-agent.socket
install -m 0644 "$SCRIPT_DIR/systemd/wiregate.conf" /usr/lib/tmpfiles.d/wiregate.conf
install -m 0644 "$SCRIPT_DIR/compose.yaml" /etc/wiregate-web/compose.yaml

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

{
  printf 'listen_address: "0.0.0.0:8443"\n'
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
  printf 'wiregate-web health status: %s\n' "$HEALTH" >&2
  exit 1
}

BOOTSTRAP_TOKEN=$(docker compose \
  --env-file /etc/wiregate-web/runtime.env \
  -f /etc/wiregate-web/compose.yaml exec -T wiregate-web \
  /wiregate-web bootstrap-token -config /etc/wiregate/web.yaml -ttl 15m)

case "$PUBLIC_HOST" in
  *:*) DISPLAY_HOST="[$PUBLIC_HOST]" ;;
  *) DISPLAY_HOST=$PUBLIC_HOST ;;
esac
printf '\n%s\n' "WireGate technical POC installed successfully."
printf 'URL: https://%s:%s/\n' "$DISPLAY_HOST" "$WEB_PORT"
printf 'Bootstrap token (valid for 15 minutes): %s\n' "$BOOTSTRAP_TOKEN"
printf '%s\n' "Complete the first-admin form immediately, then store a backup of /etc/wiregate/keys and both databases."
