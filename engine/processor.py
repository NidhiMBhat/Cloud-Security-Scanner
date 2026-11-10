# engine/processor.py
import argparse
import json

from engine.database import ScanDatabase
from engine.scoring import evaluate_bucket_security


def load_scan_file(file_path: str):
    """Load normalized cloud scan JSON from disk."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        if all(key in data for key in ("bucket_name", "provider", "scan_time")):
            return [data]
        for key in ("records", "results", "buckets", "data"):
            if key in data:
                data = data[key]
                break

    if not isinstance(data, list):
        raise ValueError(f"Unsupported JSON structure in {file_path}. Expected a list of bucket records.")

    return data


def process_scan_file(file_path: str):
    """Read a saved scan JSON file and process it using the existing engine logic."""
    raw_records = load_scan_file(file_path)
    return process_scans(raw_records)


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
    parser = argparse.ArgumentParser(description="Process a saved cloud scan JSON file with the existing security engine.")
    parser.add_argument("json_file", nargs="?", default="aws_scan_output.json", help="Path to AWS or GCP scan JSON output")
    args = parser.parse_args()

    try:
        results = process_scan_file(args.json_file)
    except FileNotFoundError:
        raise SystemExit(f"File not found: {args.json_file}")
    except ValueError as exc:
        raise SystemExit(str(exc))

    print(json.dumps(results, indent=2))
