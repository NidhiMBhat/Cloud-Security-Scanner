"""
Cloud Security Scanner — GCP Module (Person 2)
Provides discovery, configuration collection, and effective public access
auditing for Google Cloud Storage buckets.
"""

from typing import Any

__all__ = ["scan_gcp_storage_buckets"]


def __getattr__(name: str) -> Any:
    if name == "scan_gcp_storage_buckets":
        from .gcp_scanner import scan_gcp_storage_buckets
        return scan_gcp_storage_buckets
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
