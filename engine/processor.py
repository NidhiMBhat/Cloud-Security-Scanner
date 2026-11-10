# engine/processor.py

from engine.scoring import evaluate_bucket_security
from engine.database import ScanDatabase

def process_scans(raw_records: list):
    """
    Processes raw input records from Person 1 or 2, 
    computes scores, checks drift against SQLite, and builds Person 4's contract.
    """
    db = ScanDatabase()
    output_contract = []

    for record in raw_records:
        bucket_name = record["bucket_name"]
        provider = record["provider"]
        scan_time = record["scan_time"]

        # 1. Score and map findings
        risk_score, severity, findings = evaluate_bucket_security(record)
        is_public = record.get("effective_public_read", False)

        # 2. Check drift against previous scan in DB
        prev_scan = db.get_previous_scan(bucket_name)
        drift_data = {"changed": False, "change": "no_change"}

        if prev_scan:
            prev_public = prev_scan["effective_public_read"]
            if prev_public != is_public:
                old_state = "public" if prev_public else "private"
                new_state = "public" if is_public else "private"
                drift_data = {
                    "changed": True,
                    "change": f"{old_state} -> {new_state}"
                }
            elif prev_scan["risk_score"] != risk_score:
                diff = risk_score - prev_scan["risk_score"]
                drift_data = {
                    "changed": True,
                    "change": f"risk score shifted by {diff:+d}"
                }

        # 3. Save current scan to history
        db.save_scan(
            bucket_name=bucket_name,
            provider=provider,
            scan_time=scan_time,
            risk_score=risk_score,
            severity=severity,
            findings=findings,
            effective_public_read=is_public
        )

        # 4. Construct output contract for Person 4
        bucket_output = {
            "bucket_name": bucket_name,
            "provider": provider,
            "risk_score": risk_score,
            "severity": severity,
            "findings": findings,
            "drift": drift_data
        }
        output_contract.append(bucket_output)

    return output_contract

if __name__ == "__main__":
    # Test stub using mock input from Person 1 contract
    sample_input = [
        {
            "provider": "aws",
            "bucket_name": "example-leaky-bucket",
            "scan_time": "2026-11-10T10:00:00Z",
            "block_public_access": False,
            "effective_public_read": True,
            "effective_public_write": False,
            "encryption_enabled": False,
            "logging_enabled": False,
            "versioning_enabled": True,
            "wildcard_principal": True,
            "public_acl_detected": False,
            "overly_permissive_iam": [],
            "raw_evidence": "Policy statement allows Principal *"
        }
    ]

    results = process_scans(sample_input)
    import json
    print(json.dumps(results, indent=2))