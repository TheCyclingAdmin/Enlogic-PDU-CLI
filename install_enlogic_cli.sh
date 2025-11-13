#!/usr/bin/env bash
set -euo pipefail

PREFIX="${HOME}/.local/enlogic-cli"
BIN_DIR="${HOME}/.local/bin"
SRC_DIR="${PREFIX}/src"
WRAP="${BIN_DIR}/enlogic_cli"

# Backups
ts="$(date +'%Y%m%d-%H%M%S')"
month="$(date +'%m')"
day="$(date +'%d')"
bdir="${HOME}/backups/enlogic/${month}/${day}"
mkdir -p "${bdir}"
tmpdir="$(mktemp -d)"
mkdir -p "${tmpdir}/snapshot"
[ -d "${PREFIX}" ] && cp -a "${PREFIX}" "${tmpdir}/snapshot/enlogic-cli" || true
[ -f "${HOME}/.enlogic.ini" ] && cp -a "${HOME}/.enlogic.ini" "${tmpdir}/snapshot/" || true
[ -f "${HOME}/.enlogic-hosts.ini" ] && cp -a "${HOME}/.enlogic-hosts.ini" "${tmpdir}/snapshot/" || true
[ -f "${BIN_DIR}/enlogic_cli" ] && cp -a "${BIN_DIR}/enlogic_cli" "${tmpdir}/snapshot/" || true
[ -f "${BIN_DIR}/enlogic-cli" ] && cp -a "${BIN_DIR}/enlogic-cli" "${tmpdir}/snapshot/" || true
[ -f "${HOME}/.bashrc" ] && cp -a "${HOME}/.bashrc" "${tmpdir}/snapshot/bashrc" || true
tar -C "${tmpdir}" -czf "${bdir}/enlogic.${ts}.tar.gz" snapshot >/dev/null 2>&1 || true
rm -rf "${tmpdir}"
echo "[*] Backup archived at ${bdir}/enlogic.${ts}.tar.gz"

# Prereqs
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y python3 python3-venv python3-pip ca-certificates openssl
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y python3 python3-venv python3-pip ca-certificates openssl
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y python3 python3-venv python3-pip ca-certificates openssl
else
  echo "[!] Ensure Python 3.9+, venv, and CA certificates are installed."
fi

# Install
rm -rf "${SRC_DIR}"
mkdir -p "${SRC_DIR}" "${BIN_DIR}"
cp -a enlogic_cli.py enlogic_core.py enlogic_text.py enlogic_errors.py README.md requirements.txt enlogic.ini.sample enlogic-hosts.sample.ini "${SRC_DIR}/"

python3 -m venv "${PREFIX}/venv"
source "${PREFIX}/venv/bin/activate"
pip install --upgrade pip
pip install -r "${SRC_DIR}/requirements.txt"

# Wrapper
cat > "${WRAP}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="${HOME}/.local/enlogic-cli"
source "${ROOT}/venv/bin/activate"
export PYTHONPATH="${ROOT}/src"
exec python3 "${ROOT}/src/enlogic_cli.py" "$@"
EOF
chmod +x "${WRAP}"
[ -f "${BIN_DIR}/enlogic-cli" ] && mv -f "${BIN_DIR}/enlogic-cli" "${BIN_DIR}/enlogic-cli.old.${ts}" || true

# PATH and bash profile
[ -f "${HOME}/.bashrc" ] && cp -a "${HOME}/.bashrc" "${HOME}/.bashrc.bak.${ts}" || true
touch "${HOME}/.bashrc"
# remove old alias/function lines
sed -i.bak '/alias\s\+enlogic_cli=/d;/function\s\+enlogic_cli/d' "${HOME}/.bashrc" || true
# ensure ~/.local/bin on PATH
if ! grep -q 'export PATH=.*\$HOME/.local/bin' "${HOME}/.bashrc"; then
  cat >> "${HOME}/.bashrc" <<'EOPATH'
# >>> enlogic_cli PATH setup >>> 
if [ -d "$HOME/.local/bin" ]; then
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH" ;;
  esac
fi
# <<< enlogic_cli PATH setup <<<
EOPATH
fi

echo "[*] Installed wrapper at ${WRAP}"
echo "[*] Restart your shell or 'source ~/.bashrc' to pick up PATH changes."
