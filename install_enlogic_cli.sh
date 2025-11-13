#!/usr/bin/env bash
set -euo pipefail
PREFIX="${HOME}/.local/enlogic-cli"
BIN_DIR="${HOME}/.local/bin"
SRC_DIR="${PREFIX}/src"

echo "[*] Installing to ${PREFIX} ..."
rm -rf "${SRC_DIR}"
mkdir -p "${SRC_DIR}" "${BIN_DIR}"

cp -a enlogic_cli.py enlogic_core.py enlogic_text.py enlogic_errors.py README.md requirements.txt enlogic.ini.sample enlogic-hosts.sample.ini "${SRC_DIR}/"

if command -v apt-get >/dev/null 2>&1; then
  echo "[*] Using apt-get"
  sudo apt-get update -y
  sudo apt-get install -y python3 python3-venv python3-pip
elif command -v dnf >/dev/null 2>&1; then
  echo "[*] Using dnf"
  sudo dnf install -y python3 python3-venv python3-pip
elif command -v yum >/dev/null 2>&1; then
  echo "[*] Using yum"
  sudo yum install -y python3 python3-venv python3-pip
else
  echo "[!] Ensure Python 3.9+ and venv are installed."
fi

python3 -m venv "${PREFIX}/venv"
source "${PREFIX}/venv/bin/activate"
pip install --upgrade pip
pip install -r "${SRC_DIR}/requirements.txt"

WRAP="${BIN_DIR}/enlogic-cli"
cat > "${WRAP}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="${HOME}/.local/enlogic-cli"
source "${ROOT}/venv/bin/activate"
PYTHONPATH="${ROOT}/src" exec python3 "${ROOT}/src/enlogic_cli.py" "$@"
EOF
chmod +x "${WRAP}"
echo "[*] Installed wrapper at ${WRAP}"
echo "[*] Done."
