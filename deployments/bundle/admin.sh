#!/bin/sh

# File: deployments/bundle/admin.sh
# Project: WireGate
# Copyright (c) 2026 Thiep Wong
# SPDX-License-Identifier: MIT
# Author: Thiep Wong
# Email: thiep.wong@gmail.com
# Date: 2026-09-09
# Description: Perform root-authorized WireGate administrative recovery.

set -eu

ACCESS_STATE=/etc/wiregate-web/access.state
WEB_ACCESS=/usr/sbin/wiregate-web-access
WEB_BINARY=/usr/lib/wiregate/wiregate-web
WEB_CONFIG=/etc/wiregate-web/web.yaml
RESTORE_WEB=0

usage() {
  printf '%s\n' \
    "Usage:" \
    "  sudo wiregate-admin reset-password --username <admin>"
}

fail() {
  printf 'wiregate-admin: %s\n' "$1" >&2
  exit 1
}

restore_web() {
  if [ "$RESTORE_WEB" -eq 1 ]; then
    RESTORE_WEB=0
    "$WEB_ACCESS" enable || printf '%s\n' \
      "wiregate-admin: password operation finished, but web restart failed" >&2
  fi
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ "$#" -ge 1 ] || { usage >&2; exit 2; }
COMMAND=$1
shift

case "$COMMAND" in
  reset-password)
    [ "$#" -eq 2 ] && [ "$1" = --username ] && [ -n "$2" ] || {
      usage >&2
      exit 2
    }
    command -v runuser >/dev/null 2>&1 || fail "required command is missing: runuser"
    [ -x "$WEB_ACCESS" ] || fail "wiregate-web-access is missing"
    [ -x "$WEB_BINARY" ] || fail "wiregate-web binary is missing"
    [ -f "$WEB_CONFIG" ] || fail "web config is missing"

    CURRENT_ACCESS=enabled
    if [ -f "$ACCESS_STATE" ]; then
      CURRENT_ACCESS=$(awk 'NR == 1 { print; exit }' "$ACCESS_STATE")
    fi
    case "$CURRENT_ACCESS" in
      enabled)
        RESTORE_WEB=1
        trap restore_web EXIT
        trap 'exit 130' HUP INT TERM
        ;;
      disabled) ;;
      *) fail "unsupported web access state: $CURRENT_ACCESS" ;;
    esac
    "$WEB_ACCESS" disable

    RESET_RESULT=0
    runuser -u wiregate-web -- \
      "$WEB_BINARY" reset-password \
      -config "$WEB_CONFIG" -username "$2" || RESET_RESULT=$?

    if [ "$RESTORE_WEB" -eq 1 ]; then
      RESTORE_WEB=0
      if ! "$WEB_ACCESS" enable; then
        printf '%s\n' \
          "wiregate-admin: web restart failed; run 'sudo wiregate-web-access enable' after checking logs" >&2
        exit 1
      fi
    fi
    trap - EXIT HUP INT TERM
    exit "$RESET_RESULT"
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
