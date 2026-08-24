#!/bin/sh

# File: src/scripts/check-headers.sh
# Project: WireGate
# Author: Thiep Wong
# Email: thiep.wong@gmail.com
# Date: 2026-08-24
# Description: Validates standard headers in maintained WireGate code files.

set -eu

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SOURCE_DIR/.." && pwd)
DEPLOYMENTS_DIR="$PROJECT_DIR/deployments"
MISSING_HEADERS=$(mktemp)
trap 'rm -f "$MISSING_HEADERS"' EXIT HUP INT TERM

find "$SOURCE_DIR" "$DEPLOYMENTS_DIR" -type f \( \
  -name '*.go' -o \
  -name '*.proto' -o \
  -name '*.sql' -o \
  -name '*.sh' -o \
  -name '*.yaml' -o \
  -name '*.js' -o \
  -name '*.css' -o \
  -name '*.html' -o \
  -name 'Dockerfile*' -o \
  -name 'Makefile' -o \
  -name '*.service' -o \
  -name '*.socket' -o \
  -name '*.conf' -o \
  -name 'go.mod' \
\) ! -path "$SOURCE_DIR/gen/*" -exec sh -c '
  project_dir=$1
  shift
  for file do
    relative=${file#"$project_dir"/}
    missing=
    grep -Fq "File: $relative" "$file" || missing="${missing} File"
    grep -Fq "Project: WireGate" "$file" || missing="${missing} Project"
    grep -Fq "Author: Thiep Wong" "$file" || missing="${missing} Author"
    grep -Fq "Email: thiep.wong@gmail.com" "$file" || missing="${missing} Email"
    grep -Eq "Date: [0-9]{4}-[0-9]{2}-[0-9]{2}" "$file" || missing="${missing} Date"
    grep -Eq "Description: .+" "$file" || missing="${missing} Description"
    if [ -n "$missing" ]; then
      printf "%s: missing%s\n" "$relative" "$missing"
    fi
  done
' sh "$PROJECT_DIR" {} + > "$MISSING_HEADERS"

if [ -s "$MISSING_HEADERS" ]; then
  printf '%s\n' 'Code header validation failed:' >&2
  cat "$MISSING_HEADERS" >&2
  exit 1
fi

printf '%s\n' 'Code headers are valid.'
