#!/bin/sh

# File: deployments/bundle/upgrade.sh
# Project: WireGate
# Copyright (c) 2026 Thiep Wong
# SPDX-License-Identifier: MIT
# Author: Thiep Wong
# Email: thiep.wong@gmail.com
# Date: 2026-08-24
# Description: WireGate build or deployment script.

set -eu

[ "$(id -u)" -eq 0 ] || {
  printf '%s\n' "upgrade.sh must run as root" >&2
  exit 1
}

for command_name in systemctl install awk uname cp date sed; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Required command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for required_path in \
  "$SCRIPT_DIR/ARCH" \
  "$SCRIPT_DIR/VERSION" \
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
VERSION=$(awk 'NR == 1 { print; exit }' "$SCRIPT_DIR/VERSION")
case "$(uname -m)" in
  x86_64) HOST_ARCH=amd64 ;;
  aarch64|arm64) HOST_ARCH=arm64 ;;
  *) printf 'Unsupported host architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac
[ "$BUNDLE_ARCH" = "$HOST_ARCH" ] || {
  printf 'Bundle architecture %s does not match host %s\n' "$BUNDLE_ARCH" "$HOST_ARCH" >&2
  exit 1
}

if [ -f /etc/wiregate-web/runtime.mode ]; then
  WEB_RUNTIME=$(awk 'NR == 1 { print; exit }' /etc/wiregate-web/runtime.mode)
elif [ -f /etc/wiregate-web/runtime.env ]; then
  # Bundles before native web support only provided the Docker runtime.
  WEB_RUNTIME=docker
else
  printf '%s\n' "Cannot determine the installed web runtime" >&2
  exit 1
fi
case "$WEB_RUNTIME" in
  native)
    command -v runuser >/dev/null 2>&1 || {
      printf '%s\n' "Required command is missing: runuser" >&2
      exit 1
    }
    ;;
  docker)
    command -v docker >/dev/null 2>&1 || {
      printf '%s\n' "Docker is required to upgrade this installation" >&2
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
    ;;
  *)
    printf 'Unsupported installed web runtime: %s\n' "$WEB_RUNTIME" >&2
    exit 1
    ;;
esac

WEB_ACCESS_STATE=enabled
if [ -f /etc/wiregate-web/access.state ]; then
  WEB_ACCESS_STATE=$(awk 'NR == 1 { print; exit }' /etc/wiregate-web/access.state)
fi
case "$WEB_ACCESS_STATE" in
  enabled|disabled) ;;
  *)
    printf 'Unsupported installed web access state: %s\n' "$WEB_ACCESS_STATE" >&2
    exit 1
    ;;
esac

for required_path in \
  /usr/lib/wiregate/wiregate-agent \
  /etc/wiregate/agent.yaml \
  /var/lib/wiregate-agent/agent.db \
  /etc/wiregate-web/web.yaml \
  /var/lib/wiregate-web/web.db; do
  [ -e "$required_path" ] || {
    printf 'Existing installation is incomplete: %s is missing\n' "$required_path" >&2
    exit 1
  }
done

if [ "$WEB_RUNTIME" = native ]; then
  [ -x /usr/lib/wiregate/wiregate-web ] || {
    printf '%s\n' "Existing native web binary is missing" >&2
    exit 1
  }
else
  for required_path in \
    /etc/wiregate-web/runtime.env \
    /etc/wiregate-web/compose.yaml; do
    [ -e "$required_path" ] || {
      printf 'Existing Docker installation is incomplete: %s is missing\n' "$required_path" >&2
      exit 1
    }
  done
fi

if [ "$WEB_RUNTIME" = docker ]; then
  # Building does not touch the running container, so fail here before the
  # short maintenance window if the image context is invalid.
  IMAGE_TAG="wiregate-web:$VERSION-$HOST_ARCH"
  docker build --pull=false -f "$SCRIPT_DIR/web-image/Dockerfile" \
    -t "$IMAGE_TAG" "$SCRIPT_DIR/web-image"
  IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE_TAG")
fi

BACKUP_DIR="/var/backups/wiregate/upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
[ ! -e "$BACKUP_DIR" ] || {
  printf 'Backup path already exists: %s\n' "$BACKUP_DIR" >&2
  exit 1
}
install -d -m 0700 "$BACKUP_DIR"

if [ "$WEB_RUNTIME" = native ]; then
  systemctl stop wiregate-web.service
else
  COMPOSE="/etc/wiregate-web/compose.yaml"
  ENV_FILE="/etc/wiregate-web/runtime.env"
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" stop
fi
systemctl stop wiregate-agent.service wiregate-agent.socket

cp -a /usr/lib/wiregate "$BACKUP_DIR/"
cp -a /var/lib/wiregate-agent "$BACKUP_DIR/"
cp -a /var/lib/wiregate-web "$BACKUP_DIR/"
cp -a /etc/wiregate "$BACKUP_DIR/"
cp -a /etc/wiregate-web "$BACKUP_DIR/"
cp -a /etc/wireguard "$BACKUP_DIR/"

install -m 0755 "$SCRIPT_DIR/bin/wiregate-agent" /usr/lib/wiregate/wiregate-agent
install -m 0755 "$SCRIPT_DIR/web-access.sh" /usr/sbin/wiregate-web-access
install -m 0644 "$SCRIPT_DIR/systemd/wiregate-agent.service" /etc/systemd/system/wiregate-agent.service
install -m 0644 "$SCRIPT_DIR/systemd/wiregate-agent.socket" /etc/systemd/system/wiregate-agent.socket
install -m 0644 "$SCRIPT_DIR/systemd/wiregate.conf" /usr/lib/tmpfiles.d/wiregate.conf
install -m 0644 "$SCRIPT_DIR/compose.yaml" /etc/wiregate-web/compose.yaml
if [ "$WEB_RUNTIME" = native ]; then
  install -m 0755 "$SCRIPT_DIR/bin/wiregate-web" /usr/lib/wiregate/wiregate-web
  install -m 0644 "$SCRIPT_DIR/systemd/wiregate-web.service" /etc/systemd/system/wiregate-web.service
else
  sed -i "s|^WIREGATE_WEB_IMAGE=.*|WIREGATE_WEB_IMAGE=$IMAGE_ID|" "$ENV_FILE"
fi
printf '%s\n' "$WEB_RUNTIME" > /etc/wiregate-web/runtime.mode
chown root:root /etc/wiregate-web/runtime.mode
chmod 0600 /etc/wiregate-web/runtime.mode
printf '%s\n' "$WEB_ACCESS_STATE" > /etc/wiregate-web/access.state
chown root:root /etc/wiregate-web/access.state
chmod 0600 /etc/wiregate-web/access.state

systemctl daemon-reload
systemctl start wiregate-agent.socket wiregate-agent.service
systemctl is-active --quiet wiregate-agent.service || {
  systemctl status --no-pager wiregate-agent.service >&2 || true
  printf 'Upgrade stopped. Backup is at %s\n' "$BACKUP_DIR" >&2
  exit 1
}

if [ "$WEB_ACCESS_STATE" = disabled ]; then
  if [ "$WEB_RUNTIME" = native ]; then
    systemctl disable wiregate-web.service >/dev/null 2>&1 || true
  fi
  HEALTH=disabled
elif [ "$WEB_RUNTIME" = native ]; then
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
    printf 'Native web health is %s. Backup is at %s\n' "$HEALTH" "$BACKUP_DIR" >&2
    exit 1
  }
else
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d

  CONTAINER_ID=$(docker compose --env-file "$ENV_FILE" -f "$COMPOSE" ps -q wiregate-web)
  [ -n "$CONTAINER_ID" ] || {
    printf 'Web container was not created. Backup is at %s\n' "$BACKUP_DIR" >&2
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
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE" logs --no-color >&2 || true
    printf 'Docker web health is %s. Backup is at %s\n' "$HEALTH" "$BACKUP_DIR" >&2
    exit 1
  }
fi

printf 'WireGate upgraded to %s with %s web runtime and web access %s. Backup: %s\n' \
  "$VERSION" "$WEB_RUNTIME" "$WEB_ACCESS_STATE" "$BACKUP_DIR"
