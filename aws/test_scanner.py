import unittest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from .aws_checks import (
    check_encryption,
    check_logging,
    check_versioning,
    check_block_public_access,
    check_account_public_access_block,
    check_bucket_policy_public
)


class TestAWSScannerSecurityChecks(unittest.TestCase):

    def setUp(self):
        """Initialize a mock boto3 S3 client before each test."""
        self.mock_client = MagicMock()

    def test_check_encryption_enabled(self):
        """Test when default encryption is correctly configured."""
        self.mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {}
        }
        self.assertTrue(check_encryption(self.mock_client, "test-bucket"))

    def test_check_encryption_missing(self):
        """Test when encryption configuration is missing (raises ClientError)."""
        error_response = {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}
        self.mock_client.get_bucket_encryption.side_effect = ClientError(error_response, "GetBucketEncryption")
        
        self.assertFalse(check_encryption(self.mock_client, "test-bucket"))

    def test_check_logging_enabled(self):
        """Test when access logging is enabled."""
        self.mock_client.get_bucket_logging.return_value = {
            "LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "logs/"}
        }
        self.assertTrue(check_logging(self.mock_client, "test-bucket"))

    def test_check_logging_disabled(self):
        """Test when access logging is disabled (empty response)."""
        self.mock_client.get_bucket_logging.return_value = {}
        self.assertFalse(check_logging(self.mock_client, "test-bucket"))

    def test_check_versioning_enabled(self):
        """Test when bucket versioning is enabled."""
        self.mock_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        self.assertTrue(check_versioning(self.mock_client, "test-bucket"))

    def test_check_block_public_access_fully_enabled(self):
        """Test when all Block Public Access rules are active."""
        self.mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        self.assertTrue(check_block_public_access(self.mock_client, "test-bucket"))

    def test_check_account_public_access_block(self):
        """Test account-level Block Public Access check."""
        self.mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
        result = check_account_public_access_block(self.mock_client)
        self.assertTrue(result["account_bpa_enabled"])

    def test_check_bucket_policy_public_read(self):
        """Test detection of public wildcard read policy."""
        public_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*"
            }]
        }
        self.mock_client.get_bucket_policy.return_value = {"Policy": str(public_policy).replace("'", '"')}
        
        res = check_bucket_policy_public(self.mock_client, "test-bucket")
        self.assertTrue(res["wildcard_principal"])
        self.assertTrue(res["effective_public_read"])
        self.assertFalse(res["effective_public_write"])

if __name__ == "__main__":
    unittest.main()