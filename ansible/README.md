# Ansible Audit Playbook for CVE-2026-114938 (Java4Shell)

Standalone Ansible playbook (`audit_cve_2026_114938.yml`) to remotely audit target Linux servers for exposure to **CVE-2026-114938** using `ansible.builtin` modules.

## What It Checks

On each target host, the playbook performs 4 read-only defensive checks:

1. **Host Architecture**: Evaluates `ansible_facts['architecture']` and skips Java/container checks on non-`x86_64` hosts.
2. **Host Java Binary Inventory**: Searches `/usr`, `/opt`, `/home`, and `/var` for executable `bin/java` binaries and checks `-XX:+UnlockDiagnosticVMOptions -XX:+PrintFlagsFinal -version` for `UseBASE64Intrinsics`.
3. **Active Host Java Processes**: Inspects running `java` processes (`pgrep -fa "java"`) and `/proc/<PID>/environ` (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`) for the `-XX:-UseBASE64Intrinsics` mitigation flag.
4. **Container Runtime Audit**: Checks running **Podman** and **Docker** containers for installed `java` binaries and active `java` processes in `/proc` missing `-XX:-UseBASE64Intrinsics`.

## Inventory Setup

Edit [inventory.ini](inventory.ini) to list your target hosts under `[targets]`:

```ini
[targets]
server1.example.com ansible_user=root
192.168.1.10 ansible_user=admin
```

## Usage

### Standard audit across inventory

```bash
ansible-playbook -i ansible/inventory.ini ansible/audit_cve_2026_114938.yml
```

> **Note**: The playbook uses `become: true` by default so it can inspect `/proc/<PID>/environ` and container runtimes. For unprivileged local checks without sudo, pass `-e ansible_become=false`.

### Ad-hoc single target server check

```bash
ansible-playbook -i "target.example.com," ansible/audit_cve_2026_114938.yml -u <user> --ask-become-pass
```

### Fail CI / automation when vulnerable targets are found

By default (`fail_on_exposed: false`), the playbook reports findings and completes without failing. To fail any exposed host (non-zero exit code for CI/CD gates):

```bash
ansible-playbook -i ansible/inventory.ini ansible/audit_cve_2026_114938.yml -e fail_on_exposed=true
```

## See Also

- [Root README](../README.md) — Local Bash audit script (`audit_cve_2026_114938.sh`) and mitigation summary.
- [Container README](../container/README.md) — Red Hat UBI 9 Minimal container image for running audits via Podman/Docker.
