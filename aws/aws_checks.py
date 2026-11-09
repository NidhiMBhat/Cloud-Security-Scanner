import json
from botocore.exceptions import ClientError

def check_encryption(s3_client, bucket_name):
    """Checks if default server-side encryption is enabled."""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ["ServerSideEncryptionConfigurationNotFoundError", "NoSuchServerSideEncryptionConfiguration"]:
            return False
        return False

def check_logging(s3_client, bucket_name):
    """Checks if S3 server access logging is enabled."""
    try:
        res = s3_client.get_bucket_logging(Bucket=bucket_name)
        return "LoggingEnabled" in res
    except ClientError:
        return False

def check_versioning(s3_client, bucket_name):
    """Checks if bucket versioning is enabled."""
    try:
        res = s3_client.get_bucket_versioning(Bucket=bucket_name)
        return res.get("Status") == "Enabled"
    except ClientError:
        return False

def check_block_public_access(s3_client, bucket_name):
    """Checks if S3 Block Public Access is fully enabled for a specific bucket."""
    try:
        res = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = res.get("PublicAccessBlockConfiguration", {})
        return all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False)
        ])
    except ClientError:
        return False

def check_account_public_access_block(s3_client):
    """
    Checks AWS account-level S3 Block Public Access settings.
    Note: Account-level BPA overrides individual bucket settings.
    """
    try:
        res = s3_client.get_public_access_block()
        cfg = res.get("PublicAccessBlockConfiguration", {})
        return {
            "account_bpa_enabled": all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False)
            ]),
            "configuration": cfg
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return {"account_bpa_enabled": False, "configuration": {}}
        return {"account_bpa_enabled": False, "configuration": {}}

def check_bucket_policy_public(s3_client, bucket_name):
    """Inspects bucket policy for wildcard principals and public read/write permissions."""
    public_read, public_write, wildcard_principal = False, False, False
    raw_policy = "No policy attached"
    try:
        res = s3_client.get_bucket_policy(Bucket=bucket_name)
        raw_policy = res.get("Policy", "")
        policy_json = json.loads(raw_policy)
        for stmt in policy_json.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal")
                is_wildcard = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")
                if is_wildcard:
                    wildcard_principal = True
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    for action in actions:
                        if action == "*" or "s3:GetObject" in action:
                            public_read = True
                        if action == "*" or "s3:PutObject" in action:
                            public_write = True
    except ClientError:
        pass
    except json.JSONDecodeError:
        raw_policy = "Invalid JSON policy"
    
    return {
        "wildcard_principal": wildcard_principal,
        "effective_public_read": public_read,
        "effective_public_write": public_write,
        "raw_policy": raw_policy
    }

def check_bucket_acl_public(s3_client, bucket_name):
    """Inspects bucket ACL grants for public access."""
    try:
        res = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in res.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True
    except ClientError:
        pass
    return False