#!/usr/bin/env bash
set -euo pipefail

# Absolute path to this script
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If we're on Windows Git Bash (MSYS/MINGW/CYGWIN) and not attached to a TTY,
# open a real OS terminal (Windows Terminal if available, otherwise cmd) and re-run.
case "${OSTYPE:-}" in
  msys*|mingw*|cygwin*)
    if [[ ! -t 1 ]]; then
      # Try Windows Terminal first
      if command -v wt.exe >/dev/null 2>&1; then
        wt.exe -w 0 new-tab --title VEACOR -- bash -lc "\"$SCRIPT_PATH\"; echo; read -rp 'Press Enter to close... ' _"
        exit 0
      fi

      # Fallback: cmd.exe (keeps window open with /k)
      cmd.exe /c start "VEACOR" cmd.exe /k "bash -lc \"'$SCRIPT_PATH'; echo; read -rp 'Press Enter to close... ' _\""
      exit 0
    fi
  ;;
esac

cd "$PROJECT_DIR"

echo "[+] Setting up VEACOR in: $PROJECT_DIR"

# Create venv
if [[ ! -d ".venv" ]]; then
  echo "[+] Creating virtual environment (.venv)"
  python3 -m venv .venv
fi

# Activate venv
# shellcheck disable=SC1091
source ".venv/bin/activate"

echo "[+] Upgrading pip tooling"
python -m pip install --upgrade pip setuptools wheel

echo "[+] Installing dependencies"
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
echo
read -rp "Press Enter to close... " _
