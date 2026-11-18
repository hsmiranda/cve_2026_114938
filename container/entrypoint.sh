#!/usr/bin/env bash
set -euo pipefail

AUDIT_DIR="${AUDIT_DIR:-/opt/audit}"
TARGET="${target:-${TARGET:-}}"
SSH_USER="${SSH_USER:-root}"
SSH_PORT="${SSH_PORT:-22}"
MODE="${MODE:-ansible}"
FAIL_ON_EXPOSED="${FAIL_ON_EXPOSED:-false}"

usage() {
  cat <<'EOF'
Usage:
  podman run --rm -e target=<IP> cve-2026_114938
  podman run --rm cve-2026_114938 -e target=<IP>

Options / Environment Variables:
  target / TARGET   Target server ([user@]host[:port]), or 'local' / 'localhost'
  SSH_USER          SSH username (default: root)
  SSH_PORT          SSH port (default: 22)
  MODE              Execution mode: 'ansible' (default), 'ssh', or 'local'
  FAIL_ON_EXPOSED   Fail with non-zero exit code if vulnerable: true|false (default: false)

Examples:
  podman run --rm -v ~/.ssh:/root/.ssh:ro,Z cve-2026_114938 -e target=192.168.1.10
  podman run --rm -v ~/.ssh:/root/.ssh:ro,Z -e target=admin@192.168.1.10:2222 cve-2026_114938
  podman run --rm -v ~/.ssh:/root/.ssh:ro,Z -e MODE=ssh cve-2026_114938 -e target=192.168.1.10
  podman run --rm cve-2026_114938 -e target=local
EOF
}

assign_kv() {
  local kv="$1"
  local key="${kv%%=*}"
  local val="${kv#*=}"
  case "$key" in
    target|TARGET) TARGET="$val" ;;
    SSH_USER) SSH_USER="$val" ;;
    SSH_PORT) SSH_PORT="$val" ;;
    MODE) MODE="$val" ;;
    FAIL_ON_EXPOSED) FAIL_ON_EXPOSED="$val" ;;
    *)
      echo "Unknown option: ${key}" >&2
      usage >&2
      exit 1
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -e|--env)
      if [[ $# -lt 2 ]]; then
        echo "Missing value after $1" >&2
        usage >&2
        exit 1
      fi
      assign_kv "$2"
      shift 2
      ;;
    -e*=*)
      assign_kv "${1#-e}"
      shift
      ;;
    --env=*)
      assign_kv "${1#--env=}"
      shift
      ;;
    target=*|TARGET=*|SSH_USER=*|SSH_PORT=*|MODE=*|FAIL_ON_EXPOSED=*)
      assign_kv "$1"
      shift
      ;;
    -*)
      echo "Unknown flag: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -z "$TARGET" ]]; then
        TARGET="$1"
      else
        echo "Unexpected argument: $1" >&2
        usage >&2
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Error: target is required." >&2
  usage >&2
  exit 1
fi

# Parse optional [user@]host[:port]
HOST_PART="$TARGET"
if [[ "$HOST_PART" == *"@"* ]]; then
  PARSED_USER="${HOST_PART%%@*}"
  HOST_PART="${HOST_PART#*@}"
  if [[ -n "$PARSED_USER" ]]; then
    SSH_USER="$PARSED_USER"
  fi
fi

TARGET_HOST="$HOST_PART"
if [[ "$HOST_PART" =~ ^\[([^\]]+)\]:([0-9]+)$ ]]; then
  TARGET_HOST="${BASH_REMATCH[1]}"
  SSH_PORT="${BASH_REMATCH[2]}"
elif [[ "$HOST_PART" =~ ^([^:]+):([0-9]+)$ ]]; then
  TARGET_HOST="${BASH_REMATCH[1]}"
  SSH_PORT="${BASH_REMATCH[2]}"
fi

export ANSIBLE_HOST_KEY_CHECKING="${ANSIBLE_HOST_KEY_CHECKING:-False}"

if [[ "$MODE" == "local" || "$TARGET_HOST" == "local" || "$TARGET_HOST" == "localhost" || "$TARGET_HOST" == "127.0.0.1" ]]; then
  exec ansible-playbook -i "localhost," -c local "${AUDIT_DIR}/audit_cve_2026_114938.yml" \
    -e "ansible_become=false" \
    -e "fail_on_exposed=${FAIL_ON_EXPOSED}"
elif [[ "$MODE" == "ssh" ]]; then
  exec ssh -o StrictHostKeyChecking=accept-new -p "${SSH_PORT}" "${SSH_USER}@${TARGET_HOST}" "bash -s" < "${AUDIT_DIR}/audit_cve_2026_114938.sh"
elif [[ "$MODE" == "ansible" ]]; then
  exec ansible-playbook -i "${TARGET_HOST}," "${AUDIT_DIR}/audit_cve_2026_114938.yml" \
    -u "${SSH_USER}" \
    -e "ansible_port=${SSH_PORT}" \
    -e "fail_on_exposed=${FAIL_ON_EXPOSED}"
else
  echo "Error: Unsupported MODE '${MODE}'. Expected 'ansible', 'ssh', or 'local'." >&2
  exit 1
fi
