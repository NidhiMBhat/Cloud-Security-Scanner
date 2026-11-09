# engine/scoring.py

FINDING_METADATA = {
    "PUBLIC_READ": {
        "id": "CLOUD_PUBLIC_READ",
        "cis_control": "3.1",
        "severity": "critical",
        "base_score": 40,
        "explanation_key": "public_read"
    },
    "PUBLIC_WRITE": {
        "id": "CLOUD_PUBLIC_WRITE",
        "cis_control": "3.2",
        "severity": "critical",
        "base_score": 45,
        "explanation_key": "public_write"
    },
    "NO_ENCRYPTION": {
        "id": "CLOUD_UNENCRYPTED",
        "cis_control": "3.3",
        "severity": "medium",
        "base_score": 15,
        "explanation_key": "unencrypted"
    },
    "NO_LOGGING": {
        "id": "CLOUD_LOGGING_DISABLED",
        "cis_control": "3.4",
        "severity": "low",
        "base_score": 10,
        "explanation_key": "logging_disabled"
    },
    "NO_VERSIONING": {
        "id": "CLOUD_VERSIONING_DISABLED",
        "cis_control": "3.5",
        "severity": "low",
        "base_score": 5,
        "explanation_key": "versioning_disabled"
    },
    "WILDCARD_PRINCIPAL": {
        "id": "CLOUD_WILDCARD_PRINCIPAL",
        "cis_control": "3.6",
        "severity": "high",
        "base_score": 30,
        "explanation_key": "wildcard_principal"
    }
}

def evaluate_bucket_security(record: dict):
    """
    Evaluates raw cloud configuration flags and generates specific findings,
    a cumulative risk score (0-100), and an overall severity tier.
    """
    findings = []
    raw_score = 0

    # Evaluate conditions and map to findings
    if record.get("effective_public_read", False):
        meta = FINDING_METADATA["PUBLIC_READ"]
        findings.append({"id": meta["id"], "cis_control": meta["cis_control"], "explanation_key": meta["explanation_key"]})
        raw_score += meta["base_score"]

    if record.get("effective_public_write", False):
        meta = FINDING_METADATA["PUBLIC_WRITE"]
        findings.append({"id": meta["id"], "cis_control": meta["cis_control"], "explanation_key": meta["explanation_key"]})
        raw_score += meta["base_score"]

    if not record.get("encryption_enabled", True):
        meta = FINDING_METADATA["NO_ENCRYPTION"]
        findings.append({"id": meta["id"], "cis_control": meta["cis_control"], "explanation_key": meta["explanation_key"]})
        raw_score += meta["base_score"]

    if not record.get("logging_enabled", True):
        meta = FINDING_METADATA["NO_LOGGING"]
        findings.append({"id": meta["id"], "cis_control": meta["cis_control"], "explanation_key": meta["explanation_key"]})
        raw_score += meta["base_score"]

    if not record.get("versioning_enabled", True):
        meta = FINDING_METADATA["NO_VERSIONING"]
        findings.append({"id": meta["id"], "cis_control": meta["cis_control"], "explanation_key": meta["explanation_key"]})
        raw_score += meta["base_score"]

    if record.get("wildcard_principal", False):
        meta = FINDING_METADATA["WILDCARD_PRINCIPAL"]
        findings.append({"id": meta["id"], "cis_control": meta["cis_control"], "explanation_key": meta["explanation_key"]})
        raw_score += meta["base_score"]

    # Compounding penalty: extra weight if public and unencrypted/unlogged
    if record.get("effective_public_read", False) and not record.get("encryption_enabled", True):
        raw_score += 15

    # Cap risk score at 100
    risk_score = min(raw_score, 100)

    # Determine overall severity
    if risk_score >= 75:
        severity = "critical"
    elif risk_score >= 50:
        severity = "high"
    elif risk_score >= 25:
        severity = "medium"
    elif risk_score > 0:
        severity = "low"
    else:
        severity = "info"

    return risk_score, severity, findings