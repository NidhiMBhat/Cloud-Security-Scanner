"""
Cloud Security Scanner — Offline GCP Unit Test Suite (Person 2)
Comprehensive mocked tests validating GCP Cloud Storage security audits,
effective public access evaluations, inconclusive/conditional state tracking,
and normalized multi-cloud contract compatibility without live GCP credentials.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure root directory is on sys.path for direct script or test runner execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from gcp.gcp_checks import (
    check_encryption,
    check_logging,
    check_versioning,
    check_public_access_prevention,
    check_uniform_bucket_level_access,
    check_iam_policy_public,
    check_bucket_acl_public,
)
from gcp.gcp_scanner import evaluate_bucket_security, scan_gcp_storage_buckets
from gcp.gcp_access import get_storage_client, list_storage_buckets, Forbidden, GoogleAPICallError


def create_mock_bucket(
    name="test-gcp-bucket",
    pap="enforced",
    ubla=True,
    versioning=True,
    logging_bucket=None,
    kms_key=None,
    iam_bindings=None,
    iam_exception=None,
    bucket_acl_entities=None,
    default_obj_acl_entities=None
):
    """Helper to configure a realistic mock Google Cloud Storage Bucket."""
    bucket = MagicMock()
    bucket.name = name

    # Public Access Prevention & UBLA
    iam_config = MagicMock()
    iam_config.public_access_prevention = pap
    iam_config.uniform_bucket_level_access_enabled = ubla
    iam_config.uniform_bucket_level_access_locked_time = None
    bucket.iam_configuration = iam_config

    # Versioning
    bucket.versioning_enabled = versioning

    # Logging
    if logging_bucket:
        bucket.logging = {"logBucket": logging_bucket, "logObjectPrefix": "logs/"}
        bucket.get_logging.return_value = {"logBucket": logging_bucket, "logObjectPrefix": "logs/"}
    else:
        bucket.logging = None
        bucket.get_logging.return_value = None

    # Encryption
    bucket.default_kms_key_name = kms_key

    # IAM Policy
    if iam_exception:
        bucket.get_iam_policy.side_effect = iam_exception
    else:
        policy = MagicMock()
        policy.bindings = iam_bindings if iam_bindings is not None else []
        bucket.get_iam_policy.return_value = policy

    # ACLs
    acl_mock = MagicMock()
    acl_mock.get_entities.return_value = bucket_acl_entities or []
    bucket.acl = acl_mock

    default_obj_acl_mock = MagicMock()
    default_obj_acl_mock.get_entities.return_value = default_obj_acl_entities or []
    bucket.default_object_acl = default_obj_acl_mock

    return bucket


class TestGCPScannerSecurityChecks(unittest.TestCase):
    """Test suite covering all 15+ mandatory audit and edge-case scenarios."""

    def test_01_private_bucket_secure_configuration(self):
        """1. Private bucket with fully compliant secure configuration."""
        bucket = create_mock_bucket(
            pap="enforced",
            ubla=True,
            versioning=True,
            logging_bucket="audit-log-bucket",
            iam_bindings=[]
        )
        record = evaluate_bucket_security(bucket)

        self.assertEqual(record["provider"], "gcp")
        self.assertTrue(record["block_public_access"])
        self.assertFalse(record["effective_public_read"])
        self.assertFalse(record["effective_public_write"])
        self.assertTrue(record["encryption_enabled"])
        self.assertTrue(record["logging_enabled"])
        self.assertTrue(record["versioning_enabled"])
        self.assertFalse(record["wildcard_principal"])

        status = record["gcp_details"]["access_evaluation_status"]
        self.assertEqual(status["overall_status"], "DEFINITIVE")
        self.assertEqual(status["read_status"], "DEFINITIVE_PRIVATE")
        self.assertEqual(status["write_status"], "DEFINITIVE_PRIVATE")
        self.assertTrue(status["definitive"])

    def test_02_public_iam_read_permission(self):
        """2. Public IAM read permission (allUsers granted roles/storage.objectViewer)."""
        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=True,
            iam_bindings=[
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
            ]
        )
        record = evaluate_bucket_security(bucket)

        self.assertFalse(record["block_public_access"])
        self.assertTrue(record["effective_public_read"])
        self.assertFalse(record["effective_public_write"])
        self.assertTrue(record["wildcard_principal"])
        self.assertEqual(record["gcp_details"]["access_evaluation_status"]["read_status"], "DEFINITIVE_PUBLIC")

    def test_03_public_iam_write_permission(self):
        """3. Public IAM write permission (allUsers granted roles/storage.objectCreator)."""
        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=True,
            iam_bindings=[
                {"role": "roles/storage.objectCreator", "members": ["allUsers"]}
            ]
        )
        record = evaluate_bucket_security(bucket)

        self.assertFalse(record["effective_public_read"])
        self.assertTrue(record["effective_public_write"])
        self.assertTrue(record["wildcard_principal"])
        self.assertEqual(record["gcp_details"]["access_evaluation_status"]["write_status"], "DEFINITIVE_PUBLIC")

    def test_04_public_iam_binding_with_pap_enforced(self):
        """4. Public IAM binding present, but Public Access Prevention is enforced."""
        bucket = create_mock_bucket(
            pap="enforced",
            ubla=True,
            iam_bindings=[
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                {"role": "roles/storage.objectCreator", "members": ["allUsers"]}
            ]
        )
        record = evaluate_bucket_security(bucket)

        # Enforced PAP overrides all public bindings at the GCP infrastructure level
        self.assertTrue(record["block_public_access"])
        self.assertFalse(record["effective_public_read"])
        self.assertFalse(record["effective_public_write"])
        self.assertTrue(record["wildcard_principal"])

        status = record["gcp_details"]["access_evaluation_status"]
        self.assertEqual(status["read_status"], "DEFINITIVE_PRIVATE")
        self.assertEqual(status["write_status"], "DEFINITIVE_PRIVATE")
        self.assertTrue(status["definitive"])

        # Overly permissive IAM entries should note nullified status
        self.assertEqual(len(record["overly_permissive_iam"]), 2)
        self.assertEqual(record["overly_permissive_iam"][0]["status"], "nullified_by_pap")

    def test_05_pap_inherited_from_higher_level(self):
        """5. Public Access Prevention is inherited from org policy (unverified org policy)."""
        bucket = create_mock_bucket(
            pap="inherited",
            ubla=True,
            iam_bindings=[]
        )
        record = evaluate_bucket_security(bucket)

        self.assertFalse(record["block_public_access"])
        self.assertFalse(record["effective_public_read"])
        self.assertFalse(record["effective_public_write"])

        status = record["gcp_details"]["access_evaluation_status"]
        self.assertEqual(status["overall_status"], "INCONCLUSIVE")
        self.assertEqual(status["read_status"], "INCONCLUSIVE_INHERITED_PAP")
        self.assertFalse(status["definitive"])
        self.assertIn("inherited from organization policy", record["raw_evidence"])

    def test_06_uniform_bucket_level_access_enabled(self):
        """6. Uniform Bucket-Level Access enabled (legacy ACLs bypassed and ignored)."""
        acl_entity = MagicMock()
        acl_entity.identifier = "allUsers"
        acl_entity.role = "READER"

        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=True,
            iam_bindings=[],
            bucket_acl_entities=[acl_entity]
        )
        record = evaluate_bucket_security(bucket)

        # Because UBLA is enabled, the legacy ACL entity is ignored
        self.assertFalse(record["public_acl_detected"])
        self.assertFalse(record["effective_public_read"])
        self.assertEqual(record["gcp_details"]["access_evaluation_status"]["read_status"], "DEFINITIVE_PRIVATE")

    def test_07_legacy_acls_when_ubla_disabled(self):
        """7. Legacy ACLs active when Uniform Bucket-Level Access is disabled."""
        acl_entity = MagicMock()
        acl_entity.identifier = "allUsers"
        acl_entity.role = "READER"

        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=False,
            iam_bindings=[],
            bucket_acl_entities=[acl_entity]
        )
        record = evaluate_bucket_security(bucket)

        # When UBLA is disabled, legacy ACL grants effective public read
        self.assertTrue(record["public_acl_detected"])
        self.assertTrue(record["effective_public_read"])
        self.assertEqual(record["gcp_details"]["access_evaluation_status"]["read_status"], "DEFINITIVE_PUBLIC")

    def test_08_conditional_public_iam_binding(self):
        """8. Public IAM binding with conditional expression."""
        condition = {
            "title": "expiring_access",
            "expression": "request.time < timestamp('2026-12-31T00:00:00Z')"
        }
        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=True,
            iam_bindings=[
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers"],
                    "condition": condition
                }
            ]
        )
        record = evaluate_bucket_security(bucket)

        self.assertFalse(record["effective_public_read"])
        status = record["gcp_details"]["access_evaluation_status"]
        self.assertEqual(status["overall_status"], "CONDITIONAL")
        self.assertEqual(status["read_status"], "CONDITIONAL_PUBLIC")
        self.assertEqual(record["gcp_details"]["conditional_bindings_count"], 1)

    def test_09_all_authenticated_users_exposure(self):
        """9. allAuthenticatedUsers exposure (any Google account, not just internal org)."""
        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=True,
            iam_bindings=[
                {"role": "roles/storage.objectViewer", "members": ["allAuthenticatedUsers"]}
            ]
        )
        record = evaluate_bucket_security(bucket)

        self.assertTrue(record["effective_public_read"])
        self.assertTrue(record["wildcard_principal"])
        self.assertTrue(record["gcp_details"]["all_authenticated_users_detected"])
        self.assertFalse(record["gcp_details"]["all_users_detected"])

    def test_10_missing_iam_policy_permission_forbidden(self):
        """10. 403 Forbidden when caller lacks storage.buckets.getIamPolicy."""
        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=True,
            iam_exception=Forbidden("Access Denied: missing storage.buckets.getIamPolicy")
        )
        record = evaluate_bucket_security(bucket)

        # Must not falsely mark as definitively secure
        self.assertFalse(record["effective_public_read"])
        status = record["gcp_details"]["access_evaluation_status"]
        self.assertEqual(status["overall_status"], "INCONCLUSIVE")
        self.assertEqual(status["read_status"], "INCONCLUSIVE_IAM_PERMISSION_DENIED")
        self.assertFalse(status["definitive"])
        self.assertIn("403 Forbidden", record["raw_evidence"])

    def test_11_versioning_disabled(self):
        """11. Bucket versioning disabled."""
        bucket = create_mock_bucket(versioning=False)
        record = evaluate_bucket_security(bucket)

        self.assertFalse(record["versioning_enabled"])
        self.assertIn("Versioning: disabled", record["raw_evidence"])

    def test_12_logging_configuration_missing(self):
        """12. Bucket logging missing/disabled."""
        bucket = create_mock_bucket(logging_bucket=None)
        record = evaluate_bucket_security(bucket)

        self.assertFalse(record["logging_enabled"])
        self.assertIn("Logging: disabled", record["raw_evidence"])

    def test_13_cmek_vs_google_managed_encryption(self):
        """13. Customer-Managed Encryption Keys (CMEK) vs default Google-managed."""
        # A: Google-managed default
        bucket_default = create_mock_bucket(kms_key=None)
        rec_default = evaluate_bucket_security(bucket_default)
        self.assertTrue(rec_default["encryption_enabled"])
        self.assertFalse(rec_default["gcp_details"]["cmek_enabled"])
        self.assertIsNone(rec_default["gcp_details"]["cmek_key_name"])

        # B: CMEK configured
        kms_arn = "projects/my-proj/locations/us/keyRings/my-ring/cryptoKeys/my-key"
        bucket_cmek = create_mock_bucket(kms_key=kms_arn)
        rec_cmek = evaluate_bucket_security(bucket_cmek)
        self.assertTrue(rec_cmek["encryption_enabled"])
        self.assertTrue(rec_cmek["gcp_details"]["cmek_enabled"])
        self.assertEqual(rec_cmek["gcp_details"]["cmek_key_name"], kms_arn)

    def test_14_api_failures_and_discovery_pagination(self):
        """14. Discovery error handling and pagination behavior."""
        mock_client = MagicMock()
        mock_client.list_buckets.side_effect = Forbidden("403 Forbidden: Missing storage.buckets.list")
        buckets = list_storage_buckets(mock_client, project_id="proj-123")
        self.assertEqual(buckets, [])

        # Test successful list
        b1, b2 = MagicMock(), MagicMock()
        mock_client.list_buckets.side_effect = None
        mock_client.list_buckets.return_value = [b1, b2]
        discovered = list_storage_buckets(mock_client, project_id="proj-123")
        self.assertEqual(len(discovered), 2)

    def test_15_contract_compatibility_and_serialization(self):
        """15. Normalized output contract validation matching AWS schema."""
        bucket = create_mock_bucket(name="test-contract-bucket")
        record = evaluate_bucket_security(bucket)

        expected_keys = [
            "provider",
            "bucket_name",
            "scan_time",
            "block_public_access",
            "effective_public_read",
            "effective_public_write",
            "encryption_enabled",
            "logging_enabled",
            "versioning_enabled",
            "wildcard_principal",
            "public_acl_detected",
            "overly_permissive_iam",
            "raw_evidence"
        ]
        for key in expected_keys:
            self.assertIn(key, record, f"Missing required top-level contract key: {key}")

        # Check types
        self.assertEqual(record["provider"], "gcp")
        self.assertIsInstance(record["bucket_name"], str)
        self.assertIsInstance(record["scan_time"], str)
        self.assertIsInstance(record["block_public_access"], bool)
        self.assertIsInstance(record["effective_public_read"], bool)
        self.assertIsInstance(record["effective_public_write"], bool)
        self.assertIsInstance(record["encryption_enabled"], bool)
        self.assertIsInstance(record["logging_enabled"], bool)
        self.assertIsInstance(record["versioning_enabled"], bool)
        self.assertIsInstance(record["wildcard_principal"], bool)
        self.assertIsInstance(record["public_acl_detected"], bool)
        self.assertIsInstance(record["overly_permissive_iam"], list)
        self.assertIsInstance(record["raw_evidence"], str)

        # Verify JSON serializability
        import json
        serialized = json.dumps(record)
        self.assertIsInstance(serialized, str)

    def test_16_inconclusive_legacy_acls_when_ubla_disabled(self):
        """16. UBLA disabled without bucket-level public grants marks object ACLs inconclusive."""
        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=False,
            iam_bindings=[],
            bucket_acl_entities=[]
        )
        record = evaluate_bucket_security(bucket)

        status = record["gcp_details"]["access_evaluation_status"]
        self.assertEqual(status["overall_status"], "INCONCLUSIVE")
        self.assertEqual(status["read_status"], "INCONCLUSIVE_LEGACY_ACLS")
        self.assertEqual(status["write_status"], "INCONCLUSIVE_LEGACY_ACLS")

    def test_17_custom_role_on_public_principal(self):
        """17. Unresolved custom role on allUsers marks access evaluation as inconclusive."""
        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=True,
            iam_bindings=[
                {"role": "projects/my-proj/roles/customStorageRole", "members": ["allUsers"]}
            ]
        )
        record = evaluate_bucket_security(bucket)

        status = record["gcp_details"]["access_evaluation_status"]
        self.assertEqual(status["overall_status"], "INCONCLUSIVE")
        self.assertEqual(status["read_status"], "INCONCLUSIVE_CUSTOM_ROLE")
        self.assertIn("customStorageRole", record["raw_evidence"])

    def test_18_regression_real_acl_entity_structure(self):
        """18. Regression: _ACLEntity structure with .roles set and no .role attribute."""
        class MockACLEntity:
            def __init__(self, entity_type, roles):
                self.type = entity_type
                self.identifier = None
                self.roles = set(roles)
            def get_roles(self):
                return list(self.roles)
            def __str__(self):
                return self.type

        # Real Google Cloud Storage _ACLEntity has .roles and .get_roles(), but NO .role
        entity = MockACLEntity("allUsers", ["READER"])
        self.assertFalse(hasattr(entity, "role"))

        bucket = create_mock_bucket(
            pap="unspecified",
            ubla=False,
            iam_bindings=[],
            bucket_acl_entities=[entity]
        )
        record = evaluate_bucket_security(bucket)

        self.assertTrue(record["public_acl_detected"])
        self.assertTrue(record["effective_public_read"])
        self.assertFalse(record["effective_public_write"])
        self.assertEqual(record["gcp_details"]["access_evaluation_status"]["read_status"], "DEFINITIVE_PUBLIC")

    def test_19_regression_callable_get_logging_method(self):
        """19. Regression: bucket.get_logging() method on real google-cloud-storage Bucket."""
        bucket = create_mock_bucket(logging_bucket=None)
        # Simulate real Bucket where .logging attribute does NOT exist, but get_logging() does
        if hasattr(bucket, "logging"):
            delattr(bucket, "logging")
        bucket.get_logging = MagicMock(return_value={"logBucket": "audit-sink-bucket", "logObjectPrefix": "audit/"})

        record = evaluate_bucket_security(bucket)
        self.assertTrue(record["logging_enabled"])
        self.assertIn("audit-sink-bucket", record["raw_evidence"])

    def test_20_regression_package_entrypoint_and_lazy_import(self):
        """20. Regression: Package entrypoint export and warning-free runpy execution."""
        import runpy
        import warnings

        # Verify from gcp import scan_gcp_storage_buckets
        import gcp
        fn = getattr(gcp, "scan_gcp_storage_buckets", None)
        self.assertTrue(callable(fn))

        # Verify invalid attribute raises AttributeError
        with self.assertRaises(AttributeError):
            _ = gcp.non_existent_attribute

        # Verify runpy can inspect module without RuntimeWarning
        with warnings.catch_warnings(record=True) as recorded_warnings:
            warnings.simplefilter("always")
            _ = runpy._get_module_details("gcp")
            runtime_warnings = [w for w in recorded_warnings if issubclass(w.category, RuntimeWarning)]
            self.assertEqual(len(runtime_warnings), 0, f"Unexpected RuntimeWarning: {runtime_warnings}")


if __name__ == "__main__":
    unittest.main()

