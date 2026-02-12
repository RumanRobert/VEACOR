#!/usr/bin/env python3
import os
import platform
import subprocess
import sys
from pathlib import Path

BANNER = r"""
██╗░░░██╗███████╗░█████╗░░█████╗░░█████╗░██████╗░
██║░░░██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗
╚██╗░██╔╝█████╗░░███████║██║░░╚═╝██║░░██║██████╔╝
░╚████╔╝░██╔══╝░░██╔══██║██║░░██╗██║░░██║██╔══██╗
░░╚██╔╝░░███████╗██║░░██║╚█████╔╝╚█████╔╝██║░░██║
░░░╚═╝░░░╚══════╝╚═╝░░╚═╝░╚════╝░░╚════╝░╚═╝░░╚═╝
"""

def run(cmd, cwd=None):
    print(f"[+] {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=cwd)

def main():
    root = Path(__file__).resolve().parent
    os.chdir(root)

    # 1) Create venv
    venv_dir = root / ".venv"
    if not venv_dir.exists():
        run([sys.executable, "-m", "venv", str(venv_dir)])

    system = platform.system().lower()
    if system == "windows":
        py = venv_dir / "Scripts" / "python.exe"
        pip = venv_dir / "Scripts" / "pip.exe"
        veacorg = venv_dir / "Scripts" / "veacorg.exe"
    else:
        py = venv_dir / "bin" / "python"
        pip = venv_dir / "bin" / "pip"
        veacorg = venv_dir / "bin" / "veacorg"

    # 2) Install deps
    req = root / "requirements.txt"
    if not req.exists():
        raise FileNotFoundError("requirements.txt not found in project root")

    run([str(py), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    run([str(pip), "install", "-r", str(req)])

    # 3) Install project locally so `veacorg` exists
    run([str(pip), "install", "-e", "."])

    # 4) Banner + help
    print(BANNER)
    if veacorg.exists():
        run([str(veacorg), "--help"])
    else:
        # Fallback if PATH/entrypoint behavior differs
        run(["veacorg", "--help"])

    print("\n[✓] Setup complete.")

    # Keep window open if user double-clicked a wrapper
    if system == "windows":
        try:
            input("Press Enter to close... ")
        except EOFError:
            pass

if __name__ == "__main__":
    main()
