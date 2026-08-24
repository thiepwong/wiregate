#!/bin/sh

# File: deployments/bundle/uninstall.sh
# Project: WireGate
# Author: Thiep Wong
# Email: thiep.wong@gmail.com
# Date: 2026-08-24
# Description: WireGate build or deployment script.

set -eu

PURGE=0
if [ "${1:-}" = "--purge" ] && [ "${2:-}" = "--confirm-purge" ]; then
  PURGE=1
elif [ "$#" -ne 0 ]; then
  printf '%s\n' \
    "Usage: sudo ./uninstall.sh" \
    "       sudo ./uninstall.sh --purge --confirm-purge" >&2
  exit 2
fi
[ "$(id -u)" -eq 0 ] || {
  printf '%s\n' "uninstall.sh must run as root" >&2
  exit 1
}

if command -v docker >/dev/null 2>&1 &&
   [ -f /etc/wiregate-web/compose.yaml ] &&
   [ -f /etc/wiregate-web/runtime.env ]; then
  docker compose \
    --env-file /etc/wiregate-web/runtime.env \
    -f /etc/wiregate-web/compose.yaml down || true
fi
systemctl disable --now wiregate-agent.service wiregate-agent.socket 2>/dev/null || true
rm -f /etc/systemd/system/wiregate-agent.service
rm -f /etc/systemd/system/wiregate-agent.socket
rm -f /usr/lib/tmpfiles.d/wiregate.conf
rm -f /usr/lib/wiregate/wiregate-agent
systemctl daemon-reload

if [ "$PURGE" -eq 1 ]; then
  printf '%s\n' "Purging WireGate metadata, keys, TLS material and databases."
  rm -rf /etc/wiregate
  rm -rf /etc/wiregate-web
  rm -rf /var/lib/wiregate-agent
  rm -rf /var/lib/wiregate-web
  rm -rf /run/wiregate
  if command -v userdel >/dev/null 2>&1; then
    userdel wiregate-web 2>/dev/null || true
  fi
  if command -v groupdel >/dev/null 2>&1; then
    groupdel wiregate 2>/dev/null || true
  fi
else
  printf '%s\n' \
    "WireGate executables/services were removed." \
    "Configuration, keys, databases and WireGuard/network assets were preserved."
fi
