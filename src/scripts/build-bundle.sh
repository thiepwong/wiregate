#!/bin/sh
set -eu

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORKSPACE_DIR=$(CDPATH= cd -- "$SOURCE_DIR/.." && pwd)
DEPLOYMENTS_DIR=${WIREGATE_DEPLOYMENTS_DIR:-"$WORKSPACE_DIR/deployments"}
VERSION=${WIREGATE_VERSION:-0.3.0-poc}
DIST_DIR=${WIREGATE_DIST_DIR:-"$WORKSPACE_DIR/build/releases"}

if [ "$#" -eq 0 ]; then
  set -- amd64 arm64
fi

mkdir -p "$DIST_DIR"
for ARCH in "$@"; do
  case "$ARCH" in
    amd64|arm64) ;;
    *)
      printf 'Unsupported architecture: %s\n' "$ARCH" >&2
      exit 2
      ;;
  esac

  WORK_DIR=$(mktemp -d)
  BUNDLE_NAME="wiregate-$VERSION-linux-$ARCH"
  BUNDLE_DIR="$WORK_DIR/$BUNDLE_NAME"
  mkdir -p \
    "$BUNDLE_DIR/bin" \
    "$BUNDLE_DIR/systemd" \
    "$BUNDLE_DIR/web-image/rootfs/var/lib/wiregate-web"

  (
    cd "$SOURCE_DIR"
    GOCACHE="$WORKSPACE_DIR/build/cache/go-build-linux-$ARCH" \
    GOMODCACHE="$WORKSPACE_DIR/build/cache/go-mod" \
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
      go build -trimpath -ldflags="-s -w -X github.com/wiregate-project/wiregate/internal/shared/version.Version=$VERSION" \
      -o "$BUNDLE_DIR/bin/wiregate-agent" ./cmd/wiregate-agent

    GOCACHE="$WORKSPACE_DIR/build/cache/go-build-linux-$ARCH" \
    GOMODCACHE="$WORKSPACE_DIR/build/cache/go-mod" \
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
      go build -trimpath -ldflags="-s -w -X github.com/wiregate-project/wiregate/internal/shared/version.Version=$VERSION" \
      -o "$BUNDLE_DIR/web-image/wiregate-web" ./cmd/wiregate-web
  )

  install -m 0755 "$DEPLOYMENTS_DIR/bundle/install.sh" "$BUNDLE_DIR/install.sh"
  install -m 0755 "$DEPLOYMENTS_DIR/bundle/upgrade.sh" "$BUNDLE_DIR/upgrade.sh"
  install -m 0755 "$DEPLOYMENTS_DIR/bundle/uninstall.sh" "$BUNDLE_DIR/uninstall.sh"
  install -m 0644 "$DEPLOYMENTS_DIR/bundle/DEPLOY.md" "$BUNDLE_DIR/DEPLOY.md"
  install -m 0644 "$DEPLOYMENTS_DIR/bundle/compose.yaml" "$BUNDLE_DIR/compose.yaml"
  install -m 0644 "$DEPLOYMENTS_DIR/bundle/web-image.Dockerfile" "$BUNDLE_DIR/web-image/Dockerfile"
  install -m 0644 "$DEPLOYMENTS_DIR/bundle/rootfs/var/lib/wiregate-web/.keep" \
    "$BUNDLE_DIR/web-image/rootfs/var/lib/wiregate-web/.keep"
  install -m 0644 "$DEPLOYMENTS_DIR/systemd/wiregate-agent.service" \
    "$BUNDLE_DIR/systemd/wiregate-agent.service"
  install -m 0644 "$DEPLOYMENTS_DIR/systemd/wiregate-agent.socket" \
    "$BUNDLE_DIR/systemd/wiregate-agent.socket"
  install -m 0644 "$DEPLOYMENTS_DIR/systemd/wiregate.conf" \
    "$BUNDLE_DIR/systemd/wiregate.conf"
  printf '%s\n' "$VERSION" > "$BUNDLE_DIR/VERSION"
  printf '%s\n' "$ARCH" > "$BUNDLE_DIR/ARCH"

  (
    cd "$BUNDLE_DIR"
    find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort |
      while IFS= read -r FILE; do
        if command -v sha256sum >/dev/null 2>&1; then
          sha256sum "$FILE"
        else
          shasum -a 256 "$FILE"
        fi
      done > SHA256SUMS
  )

  ARCHIVE_TMP="$WORK_DIR/$BUNDLE_NAME.tar.gz"
  # Do not leak macOS Finder/provenance extended attributes into Linux
  # release archives. They otherwise produce LIBARCHIVE.xattr warnings
  # during extraction on Ubuntu.
  tar -C "$WORK_DIR" -czf "$ARCHIVE_TMP" --no-xattrs "$BUNDLE_NAME"
  install -m 0644 "$ARCHIVE_TMP" "$DIST_DIR/$BUNDLE_NAME.tar.gz"
  if command -v sha256sum >/dev/null 2>&1; then
    (
      cd "$DIST_DIR"
      sha256sum "$BUNDLE_NAME.tar.gz" > "$BUNDLE_NAME.tar.gz.sha256"
    )
  else
    ARCHIVE_HASH=$(shasum -a 256 "$DIST_DIR/$BUNDLE_NAME.tar.gz" | awk '{print $1}')
    printf '%s  %s\n' "$ARCHIVE_HASH" "$BUNDLE_NAME.tar.gz" \
      > "$DIST_DIR/$BUNDLE_NAME.tar.gz.sha256"
  fi
  rm -rf "$WORK_DIR"
  printf 'Built %s\n' "$DIST_DIR/$BUNDLE_NAME.tar.gz"
done
