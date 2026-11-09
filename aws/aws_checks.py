import json
from botocore.exceptions import ClientError

def check_encryption(s3_client, bucket_name):
    """Checks if default server-side encryption is enabled."""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code in ["ServerSideEncryptionConfigurationNotFoundError", "NoSuchServerSideEncryptionConfiguration"]:
            return False
        # If access is denied or another error occurs, return False or handle accordingly
        return False

def check_logging(s3_client, bucket_name):
    """Checks if S3 server access logging is enabled."""
    try:
        response = s3_client.get_bucket_logging(Bucket=bucket_name)
        return "LoggingEnabled" in response
    except ClientError:
        return False

def check_versioning(s3_client, bucket_name):
    """Checks if bucket versioning is enabled."""
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        return response.get("Status") == "Enabled"
    except ClientError:
        return False

def check_block_public_access(s3_client, bucket_name):
    """Checks if S3 Block Public Access is fully enabled."""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get("PublicAccessBlockConfiguration", {})
        # Returns True only if all 4 block settings are active
        return all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False)
        ])
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return False
        return False

def check_bucket_policy_public(s3_client, bucket_name):
    """Inspects bucket policy for wildcard principals and public read/write permissions."""
    public_read = False
    public_write = False
    wildcard_principal = False
    raw_policy_text = ""

    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_str = response.get("Policy", "")
        raw_policy_text = policy_str
        policy_json = json.loads(policy_str)

        for statement in policy_json.get("Statement", []):
            if statement.get("Effect") == "Allow":
                principal = statement.get("Principal")
                
                # Check for wildcard principal
                is_wildcard = False
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    is_wildcard = True
                
                if is_wildcard:
                    wildcard_principal = True
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    # Check for read actions
                    for action in actions:
                        if action == "*" or "s3:GetObject" in action or "s3:List*" in action:
                            public_read = True
                        if action == "*" or "s3:PutObject" in action or "s3:DeleteObject" in action:
                            public_write = True

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "NoSuchBucketPolicy":
            raw_policy_text = "No bucket policy attached"
        else:
            raw_policy_text = f"Error fetching policy: {e}"
    except json.JSONDecodeError:
        raw_policy_text = "Invalid JSON in bucket policy"

    return {
        "wildcard_principal": wildcard_principal,
        "effective_public_read": public_read,
        "effective_public_write": public_write,
        "raw_policy": raw_policy_text
    }

def check_bucket_acl_public(s3_client, bucket_name):
    """Inspects bucket ACL grants for public access (AllUsers / AuthenticatedUsers)."""
    public_acl = False
    try:
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in response.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                public_acl = True
                break
    except ClientError:
        pass
    return public_acl