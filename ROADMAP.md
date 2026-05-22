# Roadmap

This roadmap focuses on turning `mitm-blockpage` into a reliable, documented component for managed network environments.

## Current Baseline

- Runtime certificate generation with an automatically generated local CA.
- Self-contained HTML block page.
- Docker and Compose deployment path.
- Health check endpoint.
- GitHub Actions for CI and container publishing.
- Unit tests for certificate generation, CA loading, config, and handlers.

## Near Term

- Add release artifacts for Linux amd64 and arm64.
- Add release notes and documented image tag policy.
- Add example integrations for common redirect patterns, such as DNS sinkhole, firewall NAT, and reverse proxy setups.
- Add a documented CA rotation procedure.
- Add structured JSON logs for request and certificate generation events.

## Medium Term

- Support externally managed CA material mounted from a secret store.
- Add Prometheus metrics for requests, certificate cache hits, and certificate generation failures.
- Add configurable certificate lifetime and cache eviction.
- Add admin-facing diagnostics that report active configuration without exposing secret material.
- Add end-to-end tests that validate TLS behavior with a generated CA.

## Open Decisions

- Whether the project should remain a standalone block-page service or grow a policy API.
- Whether custom block pages should support only Go templates or also static placeholder replacement.
- Whether the default deployment target should optimize for Docker Compose, Kubernetes, or bare-metal appliance installs.
- Whether per-domain certificate keys should stay ephemeral or optionally be persisted.
