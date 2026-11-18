#!/usr/bin/env bash
set -euo pipefail

# Terminal output color definitions
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

EXPOSED_COUNT=0

echo -e "${CYAN}=== Defensive Security Audit: CVE-2026-114938 (Java4Shell) ===${NC}"
echo "Scan timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "------------------------------------------------------------"

# 1. Host Architecture Check
ARCH=$(uname -m)
echo -e "[1/4] Host Architecture: ${CYAN}${ARCH}${NC}"

if [[ "$ARCH" != "x86_64" ]]; then
  echo -e "${GREEN}[OK] Host architecture is not x86_64. The affected HotSpot Base64 intrinsic does not apply.${NC}"
  exit 0
else
  echo -e "${YELLOW}[WARNING] x86_64 architecture detected. Proceeding with Java runtime inventory...${NC}"
fi

echo "------------------------------------------------------------"

# 2. Host Filesystem Java Binary Inventory
echo -e "[2/4] Scanning host filesystem for JDK / JRE / GraalVM installations..."
JAVA_BINS=$(find /usr /opt /home /var -name "java" -type f -executable 2>/dev/null | grep -E "bin/java$" || true)

if [[ -z "$JAVA_BINS" ]]; then
  echo -e "${GREEN}[OK] No 'java' binaries found in standard host directories.${NC}"
else
  while IFS= read -r bin; do
    echo -e "\n  -> Binary found: ${CYAN}${bin}${NC}"
    VERSION_OUT=$("$bin" -version 2>&1 || true)
    echo "$VERSION_OUT" | sed 's/^/     /'

    INTRINSIC_CHECK=$("$bin" -XX:+UnlockDiagnosticVMOptions -XX:+PrintFlagsFinal -version 2>&1 | grep "UseBASE64Intrinsics" || true)
    if [[ -n "$INTRINSIC_CHECK" ]]; then
      echo -e "     ${RED}[EXPOSED] Runtime uses HotSpot x86-64 with UseBASE64Intrinsics enabled.${NC}"
      echo -e "     Flag details: $(echo "$INTRINSIC_CHECK" | xargs)"
      ((EXPOSED_COUNT++)) || true
    else
      echo -e "     ${YELLOW}[CHECK] Could not confirm UseBASE64Intrinsics (may be a custom runtime or GraalVM Native).${NC}"
    fi
  done <<<"$JAVA_BINS"
fi

echo "------------------------------------------------------------"

# 3. Running Host Java Processes Check
echo -e "[3/4] Checking active Java processes on the host..."
JAVA_PROCS=$(pgrep -fa "java" || true)

if [[ -z "$JAVA_PROCS" ]]; then
  echo -e "${GREEN}[OK] No active Java processes found on the host.${NC}"
else
  while IFS= read -r proc; do
    PID=$(echo "$proc" | awk '{print $1}')
    CMD=$(echo "$proc" | cut -d' ' -f2-)
    ENV_VARS=$(tr '\0' '\n' <"/proc/${PID}/environ" 2>/dev/null | grep -E "^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=" || true)

    if [[ "$CMD" == *"-XX:-UseBASE64Intrinsics"* || "$ENV_VARS" == *"-XX:-UseBASE64Intrinsics"* ]]; then
      echo -e "  ${GREEN}[MITIGATED] Host PID ${PID} has -XX:-UseBASE64Intrinsics active.${NC}"
    else
      echo -e "  ${RED}[VULNERABLE/UNMITIGATED] Host PID ${PID} running without disabling Base64 intrinsic:${NC}"
      echo "     Command: ${CMD:0:120}..."
      ((EXPOSED_COUNT++)) || true
    fi
  done <<<"$JAVA_PROCS"
fi

echo "------------------------------------------------------------"

# 4. Container Runtime Audit (Podman & Docker)
echo -e "[4/4] Auditing running containers for Java runtimes and active processes..."

audit_container_engine() {
  local engine="$1"
  if ! command -v "$engine" >/dev/null 2>&1; then
    return
  fi

  echo -e "\n  Checking engine: ${CYAN}${engine}${NC}"
  local containers
  containers=$("$engine" ps --format "{{.ID}}|{{.Names}}|{{.Image}}" 2>/dev/null || true)

  if [[ -z "$containers" ]]; then
    echo -e "  ${GREEN}[OK] No running containers found in ${engine}.${NC}"
    return
  fi

  while IFS='|' read -r cid cname cimage; do
    # Locate java binary inside the container
    local c_java
    c_java=$("$engine" exec "$cid" sh -c 'command -v java || find /usr /opt /app -name "java" -type f 2>/dev/null | head -n 1' 2>/dev/null || true)

    # Inspect running processes inside the container via /proc (works on minimal UBI images without ps)
    local c_proc_check
    c_proc_check=$("$engine" exec "$cid" sh -c '
            for p in /proc/[0-9]*; do
                cmd=$(tr "\0" " " < "$p/cmdline" 2>/dev/null || true)
                if echo "$cmd" | grep -q "java"; then
                    env=$(tr "\0" "\n" < "$p/environ" 2>/dev/null | grep -E "^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=" || true)
                    echo "ACTIVE_JAVA|${cmd}|${env}"
                fi
            done
        ' 2>/dev/null || true)

    if [[ -n "$c_java" || -n "$c_proc_check" ]]; then
      local c_ver="Unknown version"
      if [[ -n "$c_java" ]]; then
        c_ver=$("$engine" exec "$cid" "$c_java" -version 2>&1 | head -n 1 || echo "Unable to query version")
      fi

      if [[ -n "$c_proc_check" ]]; then
        if echo "$c_proc_check" | grep -q -- "-XX:-UseBASE64Intrinsics"; then
          echo -e "  ${GREEN}[MITIGATED] Container '${cname}' (${cimage}) is running Java (${c_ver}) with mitigation active.${NC}"
        else
          echo -e "  ${RED}[EXPOSED] Container '${cname}' (${cimage}) is actively running Java (${c_ver}) WITHOUT mitigation!${NC}"
          ((EXPOSED_COUNT++)) || true
        fi
      else
        echo -e "  ${YELLOW}[INSTALLED/IDLE] Container '${cname}' (${cimage}) contains a Java binary (${c_ver}), though no active Java process was detected.${NC}"
        ((EXPOSED_COUNT++)) || true
      fi
    else
      echo -e "  ${GREEN}[OK] Container '${cname}' (${cimage}) has no Java binary or active Java process.${NC}"
    fi
  done <<<"$containers"
}

audit_container_engine "podman"
audit_container_engine "docker"

echo "------------------------------------------------------------"
echo -e "${CYAN}=== Audit Summary & Remediation Guidance ===${NC}"
if [[ "$EXPOSED_COUNT" -gt 0 ]]; then
  echo -e "${RED}[ALERT] Found ${EXPOSED_COUNT} potentially exposed Java runtime(s) or container(s).${NC}"
  echo "Recommended immediate actions:"
  echo "  1. Update OpenJDK/JDK packages via your package manager (e.g., sudo dnf update 'java-*') or rebuild container images with patched base layers."
  echo "  2. Apply temporary runtime mitigation by injecting the following JVM flag via JAVA_TOOL_OPTIONS:"
  echo -e "     ${YELLOW}-XX:+UnlockDiagnosticVMOptions -XX:-UseBASE64Intrinsics${NC}"
  exit 1
else
  echo -e "${GREEN}[PASS] No unmitigated x86_64 HotSpot Java runtimes or containers detected.${NC}"
  exit 0
fi
