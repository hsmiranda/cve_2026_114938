# Containerized Audit for CVE-2026-114938 (Java4Shell)

Build and run a self-contained **Red Hat UBI 9 Minimal** (`registry.access.redhat.com/ubi9/ubi-minimal:latest`) container image (`cve-2026_114938`) to audit target servers for **CVE-2026-114938** using Podman or Docker.

> See also the [root README](../README.md) for local host scanning and the [Ansible README](../ansible/README.md) for direct multi-host Ansible playbooks.

## Build

From the repository root:

```bash
podman build -t cve-2026_114938 -f container/ContainerFile .
```

Or using `container/` as the build context (`Containerfile` symlinks to `ContainerFile`):

```bash
podman build -t cve-2026_114938 container
```

## Run Against a Target Server

Both standard container env-var placement and trailing argument placement are supported:

```bash
# Trailing -e argument style
podman run --rm -v ~/.ssh:/root/.ssh:ro,Z cve-2026_114938 -e target=192.168.1.10

# Standard Podman env-var style
podman run --rm -v ~/.ssh:/root/.ssh:ro,Z -e target=192.168.1.10 cve-2026_114938
```

### Custom SSH User and Port

Pass `[user@]host[:port]` in `target` (or override `SSH_USER` / `SSH_PORT`):

```bash
podman run --rm -v ~/.ssh:/root/.ssh:ro,Z -e target=admin@192.168.1.10:2222 cve-2026_114938
```

### Direct SSH Script Mode (`MODE=ssh`)

By default, the container runs the Ansible audit playbook (`MODE=ansible`). To stream and execute `audit_cve_2026_114938.sh` directly over SSH without Ansible:

```bash
podman run --rm -v ~/.ssh:/root/.ssh:ro,Z -e MODE=ssh cve-2026_114938 -e target=192.168.1.10
```

### Fail on Exposed Targets (`FAIL_ON_EXPOSED=true`)

Return a non-zero exit code when any exposure is detected (useful for CI/CD):

```bash
podman run --rm -v ~/.ssh:/root/.ssh:ro,Z -e FAIL_ON_EXPOSED=true cve-2026_114938 -e target=192.168.1.10
```

### Local Self-Check

Run the audit locally inside the container (e.g., for testing):

```bash
podman run --rm cve-2026_114938 -e target=local
```
