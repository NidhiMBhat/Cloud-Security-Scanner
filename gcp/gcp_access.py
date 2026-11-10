import os
from typing import List, Optional, Tuple, Any

try:
    from google.cloud import storage
    from google.auth import default as google_auth_default
    from google.auth.exceptions import DefaultCredentialsError
    from google.api_core.exceptions import GoogleAPICallError, Forbidden
except ImportError:
    storage = None
    google_auth_default = None

    class DefaultCredentialsError(Exception):
        """Fallback exception when google-auth is not installed."""
        pass

    class GoogleAPICallError(Exception):
        """Fallback exception when google-api-core is not installed."""
        pass

    class Forbidden(GoogleAPICallError):
        """Fallback 403 Forbidden exception."""
        pass


def get_storage_client(
    project_id: Optional[str] = None,
    credentials: Optional[Any] = None
) -> Tuple[Optional[Any], Optional[str]]:
    """
    Initializes and returns a Google Cloud Storage client using Application
    Default Credentials (ADC) or explicitly provided credentials, along with
    the resolved project ID.

    Returns:
        tuple: (storage_client, resolved_project_id)
        storage_client will be None if authentication fails or library is unavailable.
    """
    if storage is None:
        print("[-] google-cloud-storage library is not installed. Install requirements via pip.")
        return None, None

    resolved_project = (
        project_id
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCP_PROJECT_ID")
    )

    try:
        if credentials is not None:
            client = storage.Client(project=resolved_project, credentials=credentials)
            resolved_project = resolved_project or getattr(client, "project", None)
            return client, resolved_project

        if google_auth_default is not None:
            creds, default_proj = google_auth_default()
            resolved_project = resolved_project or default_proj
            client = storage.Client(project=resolved_project, credentials=creds)
            return client, resolved_project

        client = storage.Client(project=resolved_project)
        return client, resolved_project or getattr(client, "project", None)

    except DefaultCredentialsError as e:
        print(f"[-] Authentication Failure: Application Default Credentials not found. Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS. Details: {e}")
        return None, resolved_project
    except Exception as e:
        print(f"[-] Unexpected error initializing GCP Storage client: {e}")
        return None, resolved_project


def list_storage_buckets(client: Any, project_id: Optional[str] = None) -> List[Any]:
    """
    Discovers all GCS buckets accessible within the specified project.

    Args:
        client: google.cloud.storage.Client instance.
        project_id: GCP project ID to list buckets for.

    Returns:
        List of bucket objects or empty list on failure.
    """
    if not client:
        return []

    try:
        if project_id:
            buckets = list(client.list_buckets(project=project_id))
        else:
            buckets = list(client.list_buckets())
        return buckets
    except Forbidden as e:
        print(f"[-] Authorization Failure: Insufficient permissions to list buckets in project '{project_id}'. Missing 'storage.buckets.list' permission. Details: {e}")
        return []
    except GoogleAPICallError as e:
        print(f"[-] GCP API Error while listing buckets in project '{project_id}': {e}")
        return []
    except Exception as e:
        print(f"[-] Unexpected error listing GCS buckets: {e}")
        return []

