#!/usr/bin/env bash
set -euo pipefail

# --- Best-effort: if double-clicked without a TTY, try to open a terminal and rerun ---
if [[ ! -t 1 ]]; then
  SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  if command -v gnome-terminal >/dev/null 2>&1; then
    gnome-terminal -- bash -lc "\"$SCRIPT_PATH\"; echo; read -rp 'Press Enter to close... '"
    exit 0
  elif command -v konsole >/dev/null 2>&1; then
    konsole -e bash -lc "\"$SCRIPT_PATH\"; echo; read -rp 'Press Enter to close... '"
    exit 0
  elif command -v x-terminal-emulator >/dev/null 2>&1; then
    x-terminal-emulator -e bash -lc "\"$SCRIPT_PATH\"; echo; read -rp 'Press Enter to close... '"
    exit 0
  elif command -v xterm >/dev/null 2>&1; then
    xterm -e bash -lc "\"$SCRIPT_PATH\"; echo; read -rp 'Press Enter to close... '"
    exit 0
  elif command -v open >/dev/null 2>&1; then
    # macOS
    open -a Terminal "$SCRIPT_PATH"
    exit 0
  fi
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "[+] Setting up VEACORG in: $PROJECT_DIR"

# --- Create venv ---
if [[ ! -d ".venv" ]]; then
  echo "[+] Creating virtual environment (.venv)"
  python3 -m venv .venv
fi

# --- Activate venv ---
# shellcheck disable=SC1091
source ".venv/bin/activate"

echo "[+] Upgrading pip tooling"
python -m pip install --upgrade pip setuptools wheel

echo "[+] Installing Python dependencies"
pip install -r requirements.txt

echo "[+] Installing project (editable) so 'veacorg' CLI is available"
pip install -e .

echo
cat <<'BANNER'
██╗░░░██╗███████╗░█████╗░░█████╗░░█████╗░██████╗░
██║░░░██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗
╚██╗░██╔╝█████╗░░███████║██║░░╚═╝██║░░██║██████╔╝
░╚████╔╝░██╔══╝░░██╔══██║██║░░██╗██║░░██║██╔══██╗
░░╚██╔╝░░███████╗██║░░██║╚█████╔╝╚█████╔╝██║░░██║
░░░╚═╝░░░╚══════╝╚═╝░░╚═╝░╚════╝░░╚════╝░╚═╝░░╚═╝
BANNER
echo

echo "[+] Running: veacorg --help"
veacorg --help

echo
echo "[✓] Setup complete."
