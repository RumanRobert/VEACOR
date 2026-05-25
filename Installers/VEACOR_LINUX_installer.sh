#!/bin/bash
# VEACOR Installer — Linux
# Double-click in your file manager and choose "Run in Terminal".

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# .venv is one level up from the Installers folder (i.e. in VEACOR-main/)
VENV_ACTIVATE="$SCRIPT_DIR/../.venv/bin/activate"
VENV_BIN="$SCRIPT_DIR/../.venv/bin"

# ── 1. Find best available Python ─────────────────────────────────────────────
PYTHON=""
for candidate in python3.11 python3.10 python3.12 python3.9 python3; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

# ── 2. If none found, try to install Python 3.11 automatically ────────────────
if [ -z "$PYTHON" ]; then
    echo "No compatible Python found. Attempting to install Python 3.11 automatically..."
    echo ""

    if command -v apt-get &>/dev/null; then
        sudo apt-get update -y && sudo apt-get install -y python3.11
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3.11
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3.11
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm python
    elif command -v zypper &>/dev/null; then
        sudo zypper install -y python311
    else
        echo "ERROR: Could not detect your package manager."
        echo "Please install Python 3.11 manually from https://www.python.org/downloads/"
        read -rp "Press Enter to close..."
        exit 1
    fi

    for candidate in python3.11 python3.10 python3.12 python3.9 python3; do
        if command -v "$candidate" &>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    done

    if [ -z "$PYTHON" ]; then
        echo ""
        echo "ERROR: Installation seemed to complete but Python still could not be found."
        echo "Please install Python 3.11 manually from https://www.python.org/downloads/"
        read -rp "Press Enter to close..."
        exit 1
    fi

    echo ""
    echo "Python installed successfully."
    echo ""
fi

# ── 3. Run the installer ───────────────────────────────────────────────────────
VERSION=$("$PYTHON" --version 2>&1)
echo "Using $VERSION ($PYTHON)"
echo ""

"$PYTHON" VEACOR_installer.py
EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "Installer finished successfully."
else
    echo "Installer exited with code $EXIT_CODE."
fi

# ── 4. Add venv to PATH permanently ───────────────────────────────────────────
if [ -f "$VENV_ACTIVATE" ]; then
    # Resolve to absolute path so it works from anywhere
    VENV_BIN_ABS="$(cd "$VENV_BIN" && pwd)"
    EXPORT_LINE="export PATH=\"$VENV_BIN_ABS:\$PATH\"  # VEACOR venv"

    # Detect which shell config files exist and add to all of them
    ADDED=0
    for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [ -f "$RC" ]; then
            if ! grep -qF "# VEACOR venv" "$RC"; then
                echo "" >> "$RC"
                echo "$EXPORT_LINE" >> "$RC"
                echo "Added VEACOR to PATH in $RC"
                ADDED=1
            else
                echo "VEACOR already in PATH in $RC — skipping."
                ADDED=1
            fi
        fi
    done

    # If none of the common rc files exist, create ~/.bashrc
    if [ $ADDED -eq 0 ]; then
        echo "$EXPORT_LINE" >> "$HOME/.bashrc"
        echo "Created ~/.bashrc and added VEACOR to PATH."
    fi

    echo ""
    echo "VEACOR commands will be available in all new terminal windows."
    echo "To use them right now in this terminal, run:"
    echo "  source ~/.bashrc   (or ~/.zshrc if you use Zsh)"
else
    echo ""
    echo "Warning: Could not find the venv at expected path:"
    echo "  $VENV_ACTIVATE"
    echo "PATH was not updated. You may need to activate the venv manually."
fi

echo ""
read -rp "Press Enter to close..."
