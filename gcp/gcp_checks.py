"""
Cloud Security Scanner — GCP Configuration Checks (Person 2)
Granular evaluation of Google Cloud Storage bucket security configurations,
including Public Access Prevention, Uniform Bucket-Level Access, Cloud IAM,
legacy ACLs, encryption (Google-managed vs CMEK), logging, and versioning.
"""

from typing import Any, Dict, List, Optional, Set

from .gcp_access import Forbidden, GoogleAPICallError


# Standard GCP Storage Roles mapped to their security capabilities
KNOWN_STORAGE_READ_ROLES: Set[str] = {
    "roles/storage.objectViewer",
    "roles/storage.objectUser",
    "roles/storage.admin",
    "roles/storage.legacyObjectReader",
    "roles/storage.legacyBucketReader",
    "roles/storage.legacyBucketOwner",
    "roles/viewer",
    "roles/editor",
    "roles/owner",
}

KNOWN_STORAGE_WRITE_ROLES: Set[str] = {
    "roles/storage.objectCreator",
    "roles/storage.objectAdmin",
    "roles/storage.admin",
    "roles/storage.objectUser",
    "roles/storage.legacyBucketWriter",
    "roles/storage.legacyObjectOwner",
    "roles/storage.legacyBucketOwner",
    "roles/editor",
    "roles/owner",
}

PUBLIC_PRINCIPALS: Set[str] = {
    "allUsers",
    "allAuthenticatedUsers",
}


def check_encryption(bucket: Any) -> Dict[str, Any]:
    """
    Checks the default encryption configuration of the bucket.
    In Google Cloud Storage, all data is automatically encrypted at rest
    using Google-managed encryption keys. Customer-Managed Encryption Keys (CMEK)
    provide additional customer control via Cloud KMS.

    Returns:
        dict: {
            "encryption_enabled": True (always at rest in GCS),
            "cmek_enabled": bool,
            "kms_key_name": Optional[str],
            "raw_encryption": str
        }
    """
    try:
        kms_key = getattr(bucket, "default_kms_key_name", None)
        if kms_key:
            return {
                "encryption_enabled": True,
                "cmek_enabled": True,
                "kms_key_name": kms_key,
                "raw_encryption": f"CMEK enabled with KMS key: {kms_key}"
            }
        return {
            "encryption_enabled": True,
            "cmek_enabled": False,
            "kms_key_name": None,
            "raw_encryption": "Default Google-managed encryption active (AES-256)"
        }
    except Exception as e:
        return {
            "encryption_enabled": True,
            "cmek_enabled": False,
            "kms_key_name": None,
            "raw_encryption": f"Unable to inspect encryption details: {e}"
        }


def check_logging(bucket: Any) -> Dict[str, Any]:
    """
    Checks if Cloud Storage usage logging is configured on the bucket.
    Inspects bucket.get_logging() (the official google-cloud-storage method),
    bucket.logging, or bucket._properties['logging'].

    Returns:
        dict: {
            "logging_enabled": bool,
            "log_bucket": Optional[str],
            "log_object_prefix": Optional[str]
        }
    """
    try:
        logging_cfg = None
        if hasattr(bucket, "get_logging") and callable(bucket.get_logging):
            res = bucket.get_logging()
            if isinstance(res, dict):
                logging_cfg = res

        if not logging_cfg:
            raw_logging = getattr(bucket, "logging", None)
            if isinstance(raw_logging, dict):
                logging_cfg = raw_logging

        if not logging_cfg and hasattr(bucket, "_properties"):
            props = getattr(bucket, "_properties", {})
            if isinstance(props, dict) and isinstance(props.get("logging"), dict):
                logging_cfg = props.get("logging")

        logging_cfg = logging_cfg or {}

        log_bucket = logging_cfg.get("logBucket") or logging_cfg.get("log_bucket")
        log_prefix = logging_cfg.get("logObjectPrefix") or logging_cfg.get("log_object_prefix")

        # Ensure log_bucket is a valid non-empty string
        is_enabled = isinstance(log_bucket, str) and bool(log_bucket.strip())

        return {
            "logging_enabled": is_enabled,
            "log_bucket": str(log_bucket) if is_enabled else None,
            "log_object_prefix": str(log_prefix) if log_prefix and isinstance(log_prefix, str) else None
        }
    except Exception:
        return {
            "logging_enabled": False,
            "log_bucket": None,
            "log_object_prefix": None
        }


def check_versioning(bucket: Any) -> Dict[str, Any]:
    """
    Checks if object versioning is enabled on the bucket.

    Returns:
        dict: {
            "versioning_enabled": bool
        }
    """
    try:
        versioning = getattr(bucket, "versioning_enabled", False)
        return {"versioning_enabled": bool(versioning)}
    except Exception:
        return {"versioning_enabled": False}


def check_public_access_prevention(bucket: Any) -> Dict[str, Any]:
    """
    Checks Public Access Prevention (PAP) setting on the bucket.

    Values:
        - 'enforced': Public access is blocked at the bucket level.
        - 'inherited': Inherited from parent project/folder/organization policy.
        - 'unspecified': PAP is not enforced on the bucket.

    Returns:
        dict: {
            "pap_enabled": bool (True only if strictly 'enforced'),
            "status": 'enforced' | 'inherited' | 'unspecified' | 'unknown',
            "is_inherited": bool
        }
    """
    try:
        iam_config = getattr(bucket, "iam_configuration", None)
        if iam_config is None:
            return {
                "pap_enabled": False,
                "status": "unspecified",
                "is_inherited": False
            }

        # google-cloud-storage represents public_access_prevention as string or property
        pap_val = getattr(iam_config, "public_access_prevention", None)
        if not pap_val and isinstance(iam_config, dict):
            pap_val = iam_config.get("publicAccessPrevention")

        if pap_val:
            normalized_pap = str(pap_val).lower().strip()
            if normalized_pap == "enforced":
                return {
                    "pap_enabled": True,
                    "status": "enforced",
                    "is_inherited": False
                }
            elif normalized_pap == "inherited":
                return {
                    "pap_enabled": False,
                    "status": "inherited",
                    "is_inherited": True
                }

        return {
            "pap_enabled": False,
            "status": "unspecified",
            "is_inherited": False
        }
    except Exception as e:
        return {
            "pap_enabled": False,
            "status": "unknown",
            "is_inherited": False,
            "error": str(e)
        }


def check_uniform_bucket_level_access(bucket: Any) -> Dict[str, Any]:
    """
    Checks if Uniform Bucket-Level Access (UBLA) is enabled.
    When UBLA is enabled, legacy bucket and object ACLs are completely disabled,
    and access is granted exclusively through Cloud IAM.

    Returns:
        dict: {
            "ubla_enabled": bool,
            "locked_time": Optional[str]
        }
    """
    try:
        iam_config = getattr(bucket, "iam_configuration", None)
        if iam_config is None:
            return {"ubla_enabled": False, "locked_time": None}

        ubla_val = getattr(iam_config, "uniform_bucket_level_access_enabled", None)
        if ubla_val is None and isinstance(iam_config, dict):
            ubla_dict = iam_config.get("uniformBucketLevelAccess", {})
            ubla_val = ubla_dict.get("enabled", False)

        locked_time = getattr(iam_config, "uniform_bucket_level_access_locked_time", None)

        return {
            "ubla_enabled": bool(ubla_val),
            "locked_time": str(locked_time) if locked_time else None
        }
    except Exception:
        return {"ubla_enabled": False, "locked_time": None}


def check_iam_policy_public(bucket: Any) -> Dict[str, Any]:
    """
    Retrieves and inspects the bucket's Cloud IAM policy for public principals
    (allUsers, allAuthenticatedUsers).

    Differentiates between:
        - Unconditional public read/write grants
        - Conditional public bindings (which require runtime context)
        - Custom or unknown roles
        - Authorization failures (403 Forbidden on get_iam_policy)

    Returns:
        dict: IAM evaluation details, including permissions, flags, and error states.
    """
    res = {
        "iam_policy_retrieved": False,
        "access_denied": False,
        "wildcard_principal": False,
        "all_users_detected": False,
        "all_authenticated_users_detected": False,
        "public_read_unconditional": False,
        "public_write_unconditional": False,
        "conditional_bindings": [],
        "custom_roles_detected": [],
        "public_bindings": [],
        "error_message": None,
    }

    try:
        # Use requested_policy_version=3 to support IAM conditions
        policy = bucket.get_iam_policy(requested_policy_version=3)
        res["iam_policy_retrieved"] = True
    except Forbidden as e:
        res["access_denied"] = True
        res["error_message"] = f"403 Forbidden: Caller lacks 'storage.buckets.getIamPolicy' permission: {e}"
        return res
    except GoogleAPICallError as e:
        res["error_message"] = f"GCP API call error fetching IAM policy: {e}"
        return res
    except Exception as e:
        res["error_message"] = f"Unexpected error fetching IAM policy: {e}"
        return res

    # Inspect bindings
    bindings = getattr(policy, "bindings", None)
    if bindings is None and isinstance(policy, dict):
        bindings = policy.get("bindings", [])

    if not bindings:
        return res

    for binding in bindings:
        # Support dict format or Policy Binding object
        role = binding.get("role", "") if isinstance(binding, dict) else getattr(binding, "role", "")
        members = binding.get("members", []) if isinstance(binding, dict) else getattr(binding, "members", [])
        condition = binding.get("condition") if isinstance(binding, dict) else getattr(binding, "condition", None)

        public_members_in_binding = set(members).intersection(PUBLIC_PRINCIPALS)
        if not public_members_in_binding:
            continue

        res["wildcard_principal"] = True
        if "allUsers" in public_members_in_binding:
            res["all_users_detected"] = True
        if "allAuthenticatedUsers" in public_members_in_binding:
            res["all_authenticated_users_detected"] = True

        binding_record = {
            "role": role,
            "members": list(public_members_in_binding),
            "condition": condition,
        }
        res["public_bindings"].append(binding_record)

        # Check conditional binding
        if condition:
            res["conditional_bindings"].append(binding_record)
            continue

        # Unconditional binding: evaluate role permissions
        is_read_role = role in KNOWN_STORAGE_READ_ROLES
        is_write_role = role in KNOWN_STORAGE_WRITE_ROLES

        if not is_read_role and not is_write_role:
            # Custom role or non-standard role
            res["custom_roles_detected"].append(role)

        if is_read_role:
            res["public_read_unconditional"] = True
        if is_write_role:
            res["public_write_unconditional"] = True

    return res


def check_bucket_acl_public(bucket: Any, ubla_enabled: bool) -> Dict[str, Any]:
    """
    Inspects legacy bucket ACL and default object ACL for public grants.
    NOTE: If UBLA is enabled, ACLs are ignored by GCP Cloud Storage.
    If UBLA is disabled, legacy ACLs grant effective access and individual
    object ACLs can also exist.

    Returns:
        dict: {
            "acls_evaluated": bool,
            "public_acl_detected": bool,
            "public_read_acl": bool,
            "public_write_acl": bool,
            "all_authenticated_users": bool,
            "details": str
        }
    """
    if ubla_enabled:
        return {
            "acls_evaluated": False,
            "public_acl_detected": False,
            "public_read_acl": False,
            "public_write_acl": False,
            "all_authenticated_users": False,
            "details": "Uniform Bucket-Level Access is enabled; legacy ACLs are disabled and ignored."
        }

    res = {
        "acls_evaluated": True,
        "public_acl_detected": False,
        "public_read_acl": False,
        "public_write_acl": False,
        "all_authenticated_users": False,
        "details": "No public ACL grants found."
    }

    def _parse_entity_roles(entity):
        roles = set()
        # 1. Check singular role string (from mocks, dicts, or simple entities)
        role_str = getattr(entity, "role", None)
        if isinstance(role_str, str) and role_str:
            roles.add(role_str)
        # 2. Check roles attribute (set or list on _ACLEntity)
        roles_attr = getattr(entity, "roles", None)
        if isinstance(roles_attr, (set, list)):
            roles.update(roles_attr)
        # 3. Check get_roles() method on _ACLEntity
        if hasattr(entity, "get_roles") and callable(entity.get_roles):
            try:
                res = entity.get_roles()
                if isinstance(res, (set, list)):
                    roles.update(res)
            except Exception:
                pass
        # 4. Check dict representation
        if isinstance(entity, dict) and "role" in entity and isinstance(entity["role"], str):
            roles.add(entity["role"])
        return {str(r).upper() for r in roles if isinstance(r, str)}

    def _inspect_entity_list(entities):
        for entity in entities:
            entity_type = getattr(entity, "type", "") or ""
            identifier = getattr(entity, "identifier", None) or getattr(entity, "entity", None) or ""
            entity_str = str(entity)

            is_all_users = (
                entity_type == "allUsers"
                or "allUsers" in identifier
                or "allUsers" in entity_str
            )
            is_all_auth = (
                entity_type == "allAuthenticatedUsers"
                or "allAuthenticatedUsers" in identifier
                or "allAuthenticatedUsers" in entity_str
            )

            if is_all_users or is_all_auth:
                res["public_acl_detected"] = True
                if is_all_auth:
                    res["all_authenticated_users"] = True

                roles = _parse_entity_roles(entity)
                for r in roles:
                    if r in ["READER", "ROLES/STORAGE.LEGACYBUCKETREADER", "ROLES/STORAGE.LEGACYOBJECTREADER"]:
                        res["public_read_acl"] = True
                    elif r in ["WRITER", "OWNER", "ROLES/STORAGE.LEGACYBUCKETWRITER", "ROLES/STORAGE.LEGACYOBJECTOWNER", "ROLES/STORAGE.LEGACYBUCKETOWNER"]:
                        res["public_read_acl"] = True
                        res["public_write_acl"] = True

    try:
        bucket_acl = getattr(bucket, "acl", None)
        if bucket_acl and hasattr(bucket_acl, "get_entities"):
            _inspect_entity_list(bucket_acl.get_entities())

        default_obj_acl = getattr(bucket, "default_object_acl", None)
        if default_obj_acl and hasattr(default_obj_acl, "get_entities"):
            _inspect_entity_list(default_obj_acl.get_entities())

        if res["public_acl_detected"]:
            res["details"] = (
                f"Public ACL detected (Read: {res['public_read_acl']}, "
                f"Write: {res['public_write_acl']}, "
                f"allAuthenticatedUsers: {res['all_authenticated_users']})"
            )

    except Forbidden as e:
        res["details"] = f"403 Forbidden inspecting legacy ACLs: {e}"
    except Exception as e:
        res["details"] = f"Unable to inspect legacy ACLs: {e}"

    return res

