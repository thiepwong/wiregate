# Deployments

This directory contains deployment definitions, not generated build artifacts:

- `bundle/`: fresh-host installer, Compose definition, and Docker build context
  included in a release bundle.
- `docker/`: Dockerfiles and Compose definitions for development and review.
- `systemd/`: socket, service, and tmpfiles definitions for the privileged
  agent.

Run `make -C src bundle` from the repository root to combine the source with
these definitions. Generated bundles are written to `build/releases/`.

See [`bundle/DEPLOY.md`](bundle/DEPLOY.md) for the bundle installation and
operations runbook.
