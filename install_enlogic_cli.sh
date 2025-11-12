#!/usr/bin/env bash
# file: install_enlogic_cli.sh
# Installs Enlogic CLI to ~/.local/enlogic-cli with a venv and a wrapper at ~/.local/bin/enlogic-cli
# Supports recent Ubuntu (apt) and RHEL family (dnf/yum). Requires bash.

set -euo pipefail

PROJECT_NAME="enlogic-cli"
INSTALL_DIR="${HOME}/.local/${PROJECT_NAME}"
BIN_DIR="${HOME}/.local/bin"
WRAP="${BIN_DIR}/enlogic-cli"

need_cmd() { command -v "$1" >/dev/null 2>&1; }
log() { printf '%s\n' "$*" >&2; }

detect_pkg_mgr() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID_LIKE:-$ID}" in
      *debian*|*ubuntu*) echo "apt"; return;;
      *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) if need_cmd dnf; then echo "dnf"; else echo "yum"; fi; return;;
    esac
  fi
  # fallback
  if need_cmd apt; then echo "apt"; return; fi
  if need_cmd dnf; then echo "dnf"; return; fi
  if need_cmd yum; then echo "yum"; return; fi
  echo "unknown"
}

install_sys_deps() {
  local mgr="$1"
  case "$mgr" in
    apt)
      sudo apt-get update -y
      sudo apt-get install -y python3 python3-venv python3-pip
      ;;
    dnf)
      sudo dnf install -y python3 python3-venv python3-pip
      ;;
    yum)
      sudo yum install -y python3 python3-virtualenv python3-pip || sudo yum install -y python3 python3-pip
      ;;
    *)
      log "Unknown package manager. Please install python3, python3-venv, and python3-pip manually."; exit 1;;
  esac
}

main() {
  local mgr
  mgr="$(detect_pkg_mgr)"
  log "Detected package manager: ${mgr}"
  if ! need_cmd python3; then
    log "python3 not found; installing..."
    install_sys_deps "$mgr"
  fi
  if ! need_cmd python3 -V >/dev/null 2>&1; then :; fi

  PYVER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' || echo "0.0")
  MAJOR=${PYVER%.*}; MINOR=${PYVER#*.}
  if [ "${MAJOR:-0}" -lt 3 ] || [ "${MINOR:-0}" -lt 9 ]; then
    log "Python ${PYVER} found; need >= 3.9. Please upgrade your Python."; exit 1
  fi

  mkdir -p "${INSTALL_DIR}" "${BIN_DIR}"
  # Copy project files from current directory into install dir
  cp -a enlogic_cli.py enlogic_core.py enlogic_text.py requirements.txt "${INSTALL_DIR}/"

  # Create venv and install deps
  if [ ! -d "${INSTALL_DIR}/venv" ]; then
    python3 -m venv "${INSTALL_DIR}/venv"
  fi
  "${INSTALL_DIR}/venv/bin/pip" -q install --upgrade pip
  "${INSTALL_DIR}/venv/bin/pip" -q install -r "${INSTALL_DIR}/requirements.txt"

  # Wrapper script
  cat > "${WRAP}" <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${HOME}/.local/enlogic-cli"
exec "${INSTALL_DIR}/venv/bin/python" "${INSTALL_DIR}/enlogic_cli.py" "$@"
WRAP
  chmod +x "${WRAP}"

  log "Installed to ${INSTALL_DIR}."
  log "Wrapper installed at ${WRAP}"
  if ! echo ":$PATH:" | grep -q ":${BIN_DIR}:"; then
    log "Add ${BIN_DIR} to your PATH, e.g.:"
    log '  echo "export PATH=$HOME/.local/bin:$PATH" >> ~/.bashrc && source ~/.bashrc'
  fi
  log "Try: enlogic-cli --help"
}

main "$@"
