# Deployments

This directory contains deployment definitions, not generated build artifacts:

- `bundle/`: fresh-host installer, native/Docker web runtime definitions, and
  Docker build context included in a release bundle. It also provides the
  host-side `wiregate-web-access` tool for post-setup restriction or shutdown.
- `docker/`: Dockerfiles and Compose definitions for development and review.
- `systemd/`: socket, service, and tmpfiles definitions for the privileged
  agent and unprivileged native web runtime.

Run `make -C src bundle` from the repository root to combine the source with
these definitions. Generated bundles are written to `build/releases/`.

See [`bundle/DEPLOY.md`](bundle/DEPLOY.md) for the bundle installation and
operations runbook.
