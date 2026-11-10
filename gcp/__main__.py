"""
Cloud Security Scanner — GCP Module CLI Entrypoint
Allows execution via:
    python -m gcp [PROJECT_ID]
"""

from .gcp_scanner import main

if __name__ == "__main__":
    main()

