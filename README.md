# CVE-2026-114938 (Java4Shell) Defensive Security Audit

A defensive Bash audit script (`audit_cve_2026_114938.sh`) to detect potentially exposed x86-64 HotSpot Java runtimes, active host processes, and running Podman/Docker containers related to **CVE-2026-114938**.

## What It Checks

1. **Host Architecture**: Verifies whether the host is `x86_64` (exits early with `[OK]` on non-`x86_64` architectures).
2. **Host Java Binary Inventory**: Scans `/usr`, `/opt`, `/home`, and `/var` for executable `bin/java` binaries and checks whether `UseBASE64Intrinsics` is present via `-XX:+UnlockDiagnosticVMOptions -XX:+PrintFlagsFinal`.
3. **Active Host Java Processes**: Inspects running `java` processes (`pgrep -fa "java"`) and their `/proc/<PID>/environ` (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`) for the `-XX:-UseBASE64Intrinsics` mitigation flag.
4. **Container Runtime Audit**: Checks running **Podman** and **Docker** containers for installed `java` binaries and active `java` processes via `/proc` (compatible with minimal/UBI images without `ps`).

## Usage

```bash
chmod +x audit_cve_2026_114938.sh
./audit_cve_2026_114938.sh
```

> **Note**: Inspecting `/proc/<PID>/environ` for processes owned by other users or auditing rootful containers may require `sudo` or appropriate permissions.

### Exit Codes

- `0`: Non-`x86_64` host, or no unmitigated x86-64 HotSpot Java runtimes/containers detected.
- `1`: One or more potentially exposed Java runtimes, processes, or containers found.

## Mitigation

If exposed runtimes are reported, the script recommends:

1. Updating OpenJDK/JDK packages via your package manager (e.g., `sudo dnf update 'java-*'`) or rebuilding container images with patched base layers.
2. Applying temporary runtime mitigation via `JAVA_TOOL_OPTIONS` (or JVM command-line arguments):

   ```bash
   -XX:+UnlockDiagnosticVMOptions -XX:-UseBASE64Intrinsics
   ```
