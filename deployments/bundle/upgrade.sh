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

for command_name in systemctl docker install awk uname cp date; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Required command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done
docker compose version >/dev/null 2>&1 || {
  printf '%s\n' "Docker Compose v2 is required" >&2
  exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
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

for required_path in \
  /usr/lib/wiregate/wiregate-agent \
  /etc/wiregate/agent.yaml \
  /var/lib/wiregate-agent/agent.db \
  /etc/wiregate-web/runtime.env \
  /etc/wiregate-web/compose.yaml \
  /var/lib/wiregate-web/web.db; do
  [ -e "$required_path" ] || {
    printf 'Existing installation is incomplete: %s is missing\n' "$required_path" >&2
    exit 1
  }
done

# Building does not touch the running container, so fail here before the
# short maintenance window if the image context is invalid.
IMAGE_TAG="wiregate-web:$VERSION-$HOST_ARCH"
docker build --pull=false -f "$SCRIPT_DIR/web-image/Dockerfile" \
  -t "$IMAGE_TAG" "$SCRIPT_DIR/web-image"
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE_TAG")

BACKUP_DIR="/var/backups/wiregate/upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
[ ! -e "$BACKUP_DIR" ] || {
  printf 'Backup path already exists: %s\n' "$BACKUP_DIR" >&2
  exit 1
}
install -d -m 0700 "$BACKUP_DIR"

COMPOSE="/etc/wiregate-web/compose.yaml"
ENV_FILE="/etc/wiregate-web/runtime.env"
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" stop
systemctl stop wiregate-agent.service wiregate-agent.socket

cp -a /usr/lib/wiregate/wiregate-agent "$BACKUP_DIR/wiregate-agent.bin"
cp -a /var/lib/wiregate-agent "$BACKUP_DIR/"
cp -a /var/lib/wiregate-web "$BACKUP_DIR/"
cp -a /etc/wiregate "$BACKUP_DIR/"
cp -a /etc/wiregate-web "$BACKUP_DIR/"
cp -a /etc/wireguard "$BACKUP_DIR/"

install -m 0755 "$SCRIPT_DIR/bin/wiregate-agent" /usr/lib/wiregate/wiregate-agent
install -m 0644 "$SCRIPT_DIR/systemd/wiregate-agent.service" /etc/systemd/system/wiregate-agent.service
install -m 0644 "$SCRIPT_DIR/systemd/wiregate-agent.socket" /etc/systemd/system/wiregate-agent.socket
install -m 0644 "$SCRIPT_DIR/systemd/wiregate.conf" /usr/lib/tmpfiles.d/wiregate.conf
install -m 0644 "$SCRIPT_DIR/compose.yaml" "$COMPOSE"
sed -i "s|^WIREGATE_WEB_IMAGE=.*|WIREGATE_WEB_IMAGE=$IMAGE_ID|" "$ENV_FILE"

systemctl daemon-reload
systemctl start wiregate-agent.socket wiregate-agent.service
systemctl is-active --quiet wiregate-agent.service || {
  systemctl status --no-pager wiregate-agent.service >&2 || true
  printf 'Upgrade stopped. Backup is at %s\n' "$BACKUP_DIR" >&2
  exit 1
}
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
  printf 'Web health is %s. Backup is at %s\n' "$HEALTH" "$BACKUP_DIR" >&2
  exit 1
}

printf 'WireGate upgraded to %s. Backup: %s\n' "$VERSION" "$BACKUP_DIR"
