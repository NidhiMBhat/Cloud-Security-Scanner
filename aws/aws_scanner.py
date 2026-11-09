import json
from datetime import datetime

from .aws_access import get_s3_client, list_s3_buckets
from .aws_checks import (
    check_encryption,
    check_logging,
    check_versioning,
    check_block_public_access,
    check_bucket_policy_public,
    check_bucket_acl_public
)
def scan_aws_s3_buckets(region_name="us-east-1"):
    """
    Discovers S3 buckets, runs security configurations checks, 
    and outputs a list of normalized JSON records.
    """
    s3_client = get_s3_client(region_name=region_name)
    if not s3_client:
        print("[-] Aborting scan: Unable to create AWS S3 client.")
        return []

    bucket_names = list_s3_buckets(s3_client)
    print(f"[+] Discovered {len(bucket_names)} S3 bucket(s). Starting security audit...")

    scan_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    scan_results = []

    for bucket in bucket_names:
        print(f"    Scanning bucket: {bucket}...")
        
        # Run individual checks
        encryption_enabled = check_encryption(s3_client, bucket)
        logging_enabled = check_logging(s3_client, bucket)
        versioning_enabled = check_versioning(s3_client, bucket)
        bpa_enabled = check_block_public_access(s3_client, bucket)
        
        policy_results = check_bucket_policy_public(s3_client, bucket)
        public_acl_detected = check_bucket_acl_public(s3_client, bucket)

        # Determine effective public exposure (taking BPA into consideration)
        # If Block Public Access is active, it overrides public policies and ACLs in AWS.
        effective_public_read = (policy_results["effective_public_read"] or public_acl_detected) and not bpa_enabled
        effective_public_write = policy_results["effective_public_write"] and not bpa_enabled

        # Construct normalized JSON record for integration with Analysis Engine
        record = {
            "provider": "aws",
            "bucket_name": bucket,
            "scan_time": scan_timestamp,
            "block_public_access": bpa_enabled,
            "effective_public_read": effective_public_read,
            "effective_public_write": effective_public_write,
            "encryption_enabled": encryption_enabled,
            "logging_enabled": logging_enabled,
            "versioning_enabled": versioning_enabled,
            "wildcard_principal": policy_results["wildcard_principal"],
            "public_acl_detected": public_acl_detected,
            "overly_permissive_iam": [],
            "raw_evidence": f"Policy check: {policy_results['raw_policy']} | Public ACL: {public_acl_detected}"
        }

        scan_results.append(record)

    return scan_results

if __name__ == "__main__":
    results = scan_aws_s3_buckets()
    
    # Pretty print normalized JSON output for verification and team handoff
    print("\n[+] Scan Complete. Normalized JSON Output:")
    print(json.dumps(results, indent=2))
    
    # Optionally save to file for the Analysis Engine team
    with open("aws_scan_output.json", "w") as f:
        json.dump(results, f, indent=2)
    print("[+] Saved scan results to aws_scan_output.json")