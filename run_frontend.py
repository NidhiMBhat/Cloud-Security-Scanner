#!/usr/bin/env python3
"""
Cloud Security Scanner — App Launcher
Launches the Enterprise React Application (powered by Python REST backend)
or optionally the legacy Streamlit dashboard.
"""

import sys
import os
import subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(ROOT, ".venv", "bin", "python")
PYTHON = VENV_PYTHON if os.path.isfile(VENV_PYTHON) else sys.executable

def main():
    if "--streamlit" in sys.argv:
        print("[+] Launching Streamlit frontend...")
        app_path = os.path.join(ROOT, "frontend", "app.py")
        subprocess.run([PYTHON, "-m", "streamlit", "run", app_path])
    else:
        port = 8000
        for arg in sys.argv[1:]:
            if arg.isdigit():
                port = int(arg)
        
        print("=" * 64)
        print("  🛡️  CloudGuard — Enterprise Cloud Security Scanner")
        print(f"  ⚡  Web UI: http://localhost:{port}")
        print("  🔒  AWS S3 & GCP Cloud Storage Audit Platform")
        print("=" * 64)
        print(f"Starting server on http://localhost:{port} (Press Ctrl+C to stop)...")
        
        server_path = os.path.join(ROOT, "backend", "server.py")
        subprocess.run([PYTHON, server_path, str(port)])

if __name__ == "__main__":
    main()
