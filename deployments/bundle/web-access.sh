#!/bin/sh

# File: deployments/bundle/web-access.sh
# Project: WireGate
# Copyright (c) 2026 Thiep Wong
# SPDX-License-Identifier: MIT
# Author: Thiep Wong
# Email: thiep.wong@gmail.com
# Date: 2026-09-09
# Description: Restrict, disable, enable, or inspect WireGate web access.

set -eu

CONFIG=/etc/wiregate-web/web.yaml
RUNTIME_MODE=/etc/wiregate-web/runtime.mode
ACCESS_STATE=/etc/wiregate-web/access.state
ENV_FILE=/etc/wiregate-web/runtime.env
COMPOSE=/etc/wiregate-web/compose.yaml
WEB_BINARY=/usr/lib/wiregate/wiregate-web

usage() {
  printf '%s\n' \
    "Usage:" \
    "  sudo wiregate-web-access restrict --bind-address <WireGuard-or-loopback-IP>" \
    "  sudo wiregate-web-access disable" \
    "  sudo wiregate-web-access enable" \
    "  sudo wiregate-web-access status"
}

fail() {
  printf 'wiregate-web-access: %s\n' "$1" >&2
  exit 1
}

read_first_line() {
  awk 'NR == 1 { print; exit }' "$1"
}

runtime() {
  [ -f "$RUNTIME_MODE" ] || fail "cannot determine the installed web runtime"
  WEB_RUNTIME=$(read_first_line "$RUNTIME_MODE")
  case "$WEB_RUNTIME" in
    native|docker) ;;
    *) fail "unsupported installed web runtime: $WEB_RUNTIME" ;;
  esac
}

write_access_state() {
  STATE_TMP=$(mktemp /etc/wiregate-web/access.state.XXXXXX)
  printf '%s\n' "$1" > "$STATE_TMP"
  chown root:root "$STATE_TMP"
  chmod 0600 "$STATE_TMP"
  mv "$STATE_TMP" "$ACCESS_STATE"
}

native_wait_healthy() {
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if systemctl is-active --quiet wiregate-web.service &&
       runuser -u wiregate-web -- \
         "$WEB_BINARY" healthcheck -config "$CONFIG" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  return 1
}

docker_compose() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" "$@"
}

docker_container_id() {
  docker_compose ps -q wiregate-web 2>/dev/null || true
}

docker_is_running() {
  CONTAINER_ID=$(docker_container_id)
  [ -n "$CONTAINER_ID" ] &&
    [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER_ID" 2>/dev/null || true)" = true ]
}

docker_wait_healthy() {
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    CONTAINER_ID=$(docker_container_id)
    if [ -n "$CONTAINER_ID" ]; then
      HEALTH=$(docker inspect \
        --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
        "$CONTAINER_ID" 2>/dev/null || true)
      [ "$HEALTH" = healthy ] && return 0
      [ "$HEALTH" = unhealthy ] && return 1
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  return 1
}

configured_native_address() {
  awk -F\" '/^[[:space:]]*listen_address:/ { print $2; exit }' "$CONFIG"
}

configured_docker_address() {
  BIND=$(awk -F= '$1 == "WIREGATE_BIND_ADDRESS" { print substr($0, index($0, "=") + 1); exit }' "$ENV_FILE")
  PORT=$(awk -F= '$1 == "WIREGATE_WEB_PORT" { print substr($0, index($0, "=") + 1); exit }' "$ENV_FILE")
  printf '%s:%s\n' "$BIND" "$PORT"
}

is_wireguard_address() {
  for WG_INTERFACE in $(wg show interfaces); do
    if ip -o address show dev "$WG_INTERFACE" | awk -v target="$1" '
      {
        address = $4
        sub(/\/.*/, "", address)
        if (address == target) {
          found = 1
        }
      }
      END { exit found ? 0 : 1 }
    '; then
      return 0
    fi
  done
  return 1
}

validate_restricted_address() {
  case "$1" in
    ''|*[!0-9A-Fa-f:.]*)
      fail "bind address must be an IPv4 or IPv6 literal"
      ;;
    127.0.0.1|::1)
      return 0
      ;;
  esac
  is_wireguard_address "$1" || fail \
    "bind address must be localhost or belong to an active WireGuard interface"
}

native_restrict() {
  [ -f "$CONFIG" ] || fail "native web config is missing"
  [ -x "$WEB_BINARY" ] || fail "native web binary is missing"

  CURRENT_LISTEN=$(configured_native_address)
  case "$CURRENT_LISTEN" in
    *:*) WEB_PORT=${CURRENT_LISTEN##*:} ;;
    *) fail "cannot read the current native listen address" ;;
  esac
  case "$BIND_ADDRESS" in
    *:*) NEW_LISTEN="[$BIND_ADDRESS]:$WEB_PORT" ;;
    *) NEW_LISTEN="$BIND_ADDRESS:$WEB_PORT" ;;
  esac

  WAS_ACTIVE=0
  systemctl is-active --quiet wiregate-web.service && WAS_ACTIVE=1
  CONFIG_TMP=$(mktemp /etc/wiregate-web/web.yaml.XXXXXX)
  CONFIG_BACKUP=$(mktemp /etc/wiregate-web/web.yaml.backup.XXXXXX)
  cp -p "$CONFIG" "$CONFIG_BACKUP"
  if ! awk -v listen="$NEW_LISTEN" '
    BEGIN { changed = 0 }
    /^[[:space:]]*listen_address:/ {
      print "listen_address: \"" listen "\""
      changed++
      next
    }
    { print }
    END { if (changed != 1) exit 1 }
  ' "$CONFIG" > "$CONFIG_TMP"; then
    rm -f "$CONFIG_TMP" "$CONFIG_BACKUP"
    fail "web config must contain exactly one listen_address"
  fi
  chown wiregate-web:wiregate "$CONFIG_TMP"
  chmod 0640 "$CONFIG_TMP"
  if ! "$WEB_BINARY" check-config -config "$CONFIG_TMP"; then
    rm -f "$CONFIG_TMP" "$CONFIG_BACKUP"
    fail "restricted native web config is invalid"
  fi
  mv "$CONFIG_TMP" "$CONFIG"

  if [ "$WAS_ACTIVE" -eq 1 ]; then
    if ! systemctl restart wiregate-web.service || ! native_wait_healthy; then
      mv "$CONFIG_BACKUP" "$CONFIG"
      systemctl restart wiregate-web.service || true
      native_wait_healthy || true
      fail "native web failed after restriction; the previous config was restored"
    fi
  fi
  rm -f "$CONFIG_BACKUP"
  printf 'Native web is restricted to %s' "$NEW_LISTEN"
  if [ "$WAS_ACTIVE" -eq 0 ]; then
    printf '%s' ' and remains stopped'
  fi
  printf '.\n'
}

docker_restrict() {
  [ -f "$ENV_FILE" ] || fail "Docker runtime environment is missing"
  [ -f "$COMPOSE" ] || fail "Docker Compose definition is missing"
  case "$BIND_ADDRESS" in
    *:*) COMPOSE_BIND="[$BIND_ADDRESS]" ;;
    *) COMPOSE_BIND=$BIND_ADDRESS ;;
  esac

  WAS_ACTIVE=0
  docker_is_running && WAS_ACTIVE=1
  ENV_TMP=$(mktemp /etc/wiregate-web/runtime.env.XXXXXX)
  ENV_BACKUP=$(mktemp /etc/wiregate-web/runtime.env.backup.XXXXXX)
  cp -p "$ENV_FILE" "$ENV_BACKUP"
  if ! awk -v bind="$COMPOSE_BIND" '
    BEGIN { changed = 0 }
    /^WIREGATE_BIND_ADDRESS=/ {
      print "WIREGATE_BIND_ADDRESS=" bind
      changed++
      next
    }
    { print }
    END { if (changed != 1) exit 1 }
  ' "$ENV_FILE" > "$ENV_TMP"; then
    rm -f "$ENV_TMP" "$ENV_BACKUP"
    fail "runtime environment must contain exactly one WIREGATE_BIND_ADDRESS"
  fi
  chown root:root "$ENV_TMP"
  chmod 0600 "$ENV_TMP"
  if ! docker compose --env-file "$ENV_TMP" -f "$COMPOSE" config --quiet >/dev/null; then
    rm -f "$ENV_TMP" "$ENV_BACKUP"
    fail "restricted Docker runtime configuration is invalid"
  fi
  mv "$ENV_TMP" "$ENV_FILE"

  if [ "$WAS_ACTIVE" -eq 1 ]; then
    if ! docker_compose up -d || ! docker_wait_healthy; then
      mv "$ENV_BACKUP" "$ENV_FILE"
      docker_compose up -d || true
      docker_wait_healthy || true
      fail "Docker web failed after restriction; the previous config was restored"
    fi
  fi
  rm -f "$ENV_BACKUP"
  printf 'Docker web is restricted to %s' "$(configured_docker_address)"
  if [ "$WAS_ACTIVE" -eq 0 ]; then
    printf '%s' ' and remains stopped'
  fi
  printf '.\n'
}

disable_web() {
  case "$WEB_RUNTIME" in
    native)
      systemctl disable --now wiregate-web.service
      ;;
    docker)
      docker_compose down
      ;;
  esac
  write_access_state disabled
  printf '%s\n' \
    "WireGate web is disabled. The agent and WireGuard tunnels remain running." \
    "Run 'sudo wiregate-web-access enable' from the host to restore web access."
}

enable_web() {
  case "$WEB_RUNTIME" in
    native)
      systemctl enable --now wiregate-web.service
      if ! native_wait_healthy; then
        systemctl status --no-pager wiregate-web.service >&2 || true
        fail "native web did not become healthy"
      fi
      ;;
    docker)
      docker_compose up -d
      if ! docker_wait_healthy; then
        docker_compose logs --no-color >&2 || true
        fail "Docker web did not become healthy"
      fi
      ;;
  esac
  write_access_state enabled
  printf '%s\n' "WireGate web is enabled and healthy."
}

show_status() {
  ACCESS=enabled
  [ ! -f "$ACCESS_STATE" ] || ACCESS=$(read_first_line "$ACCESS_STATE")
  printf 'Runtime: %s\n' "$WEB_RUNTIME"
  printf 'Configured access state: %s\n' "$ACCESS"
  case "$WEB_RUNTIME" in
    native)
      printf 'Listen address: %s\n' "$(configured_native_address)"
      printf 'Service enabled: %s\n' "$(systemctl is-enabled wiregate-web.service 2>/dev/null || true)"
      printf 'Service active: %s\n' "$(systemctl is-active wiregate-web.service 2>/dev/null || true)"
      if systemctl is-active --quiet wiregate-web.service &&
         runuser -u wiregate-web -- \
           "$WEB_BINARY" healthcheck -config "$CONFIG" >/dev/null 2>&1; then
        printf '%s\n' "Health: healthy"
      else
        printf '%s\n' "Health: unavailable"
      fi
      ;;
    docker)
      printf 'Listen address: %s\n' "$(configured_docker_address)"
      if docker_is_running; then
        printf '%s\n' "Container active: yes"
        HEALTH=$(docker inspect \
          --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
          "$CONTAINER_ID" 2>/dev/null || true)
        if [ "$HEALTH" = healthy ]; then
          printf '%s\n' "Health: healthy"
        else
          printf '%s\n' "Health: unavailable"
        fi
      else
        printf '%s\n' "Container active: no" "Health: unavailable"
      fi
      ;;
  esac
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ "$#" -ge 1 ] || { usage >&2; exit 2; }
COMMAND=$1
shift

for command_name in awk chmod chown cp id mktemp mv rm sleep wg ip; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is missing: $command_name"
done
runtime

case "$WEB_RUNTIME" in
  native)
    for command_name in systemctl runuser; do
      command -v "$command_name" >/dev/null 2>&1 || fail "required command is missing: $command_name"
    done
    ;;
  docker)
    command -v docker >/dev/null 2>&1 || fail "Docker is required for this installation"
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
    docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"
    ;;
esac

case "$COMMAND" in
  restrict)
    [ "$#" -eq 2 ] && [ "$1" = --bind-address ] || { usage >&2; exit 2; }
    BIND_ADDRESS=$2
    validate_restricted_address "$BIND_ADDRESS"
    case "$WEB_RUNTIME" in
      native) native_restrict ;;
      docker) docker_restrict ;;
    esac
    ;;
  disable)
    [ "$#" -eq 0 ] || { usage >&2; exit 2; }
    disable_web
    ;;
  enable)
    [ "$#" -eq 0 ] || { usage >&2; exit 2; }
    enable_web
    ;;
  status)
    [ "$#" -eq 0 ] || { usage >&2; exit 2; }
    show_status
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
