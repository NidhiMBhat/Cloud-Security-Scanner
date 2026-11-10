"""
Cloud Security Scanner — Streamlit Dashboard (Plum & Aubergine Custom Palette)
Multi-cloud (AWS + GCP) storage security audit platform with CIS benchmark scoring.
"""

import json
import os
import sys
import tempfile
from datetime import datetime
from typing import Dict, List, Optional

import streamlit as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

st.set_page_config(
    page_title="Cloud Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Clean Custom Palette (No White, No Blue Gradients) ──────────────────────
# Swatch tokens: #150016, #29104A, #522C5D, #845162, #E3B8B1, #FFE3DE
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [data-testid="stAppViewContainer"], .stApp {
    background-color: #150016 !important;
    color: #FFE3DE !important;
    font-family: 'Plus Jakarta Sans', -apple-system, sans-serif !important;
}

#MainMenu, footer, header { visibility: hidden; }

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #29104A !important;
    border-right: 1px solid #522C5D !important;
}

/* Card containers */
.metric-box {
    background-color: #29104A;
    border: 1px solid #522C5D;
    border-radius: 10px;
    padding: 16px 20px;
}
.metric-box .val {
    font-size: 26px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    color: #FFE3DE;
    line-height: 1.1;
}
.metric-box .lbl {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #845162;
    margin-top: 4px;
    font-weight: 600;
}

/* Inputs */
.stTextInput input, .stSelectbox div[data-baseweb], .stTextArea textarea {
    background-color: #150016 !important;
    border: 1px solid #522C5D !important;
    border-radius: 8px !important;
    color: #FFE3DE !important;
    font-size: 13px !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
    border-color: #E3B8B1 !important;
    box-shadow: 0 0 0 1px #E3B8B1 !important;
}

/* Buttons */
.stButton > button {
    background-color: #522C5D !important;
    border: 1px solid #845162 !important;
    color: #FFE3DE !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    padding: 8px 18px !important;
}
.stButton > button:hover {
    background-color: #845162 !important;
    border-color: #E3B8B1 !important;
}

/* Expander */
.streamlit-expanderHeader {
    background-color: #29104A !important;
    border: 1px solid #522C5D !important;
    border-radius: 8px !important;
    color: #FFE3DE !important;
    font-weight: 600 !important;
    font-size: 13px !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid #522C5D !important;
    border-radius: 8px !important;
    background: #29104A !important;
}
</style>
""", unsafe_allow_html=True)


def _run_aws(access_key, secret_key, session_token, region):
    import boto3
    from aws.aws_checks import (
        check_encryption, check_logging, check_versioning,
        check_block_public_access, check_bucket_policy_public, check_bucket_acl_public
    )
    kwargs = {"region_name": region}
    if access_key:
        kwargs["aws_access_key_id"] = access_key
        kwargs["aws_secret_access_key"] = secret_key
        if session_token:
            kwargs["aws_session_token"] = session_token
    s3 = boto3.client("s3", **kwargs)
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    results = []
    for b in buckets:
        enc = check_encryption(s3, b)
        log = check_logging(s3, b)
        ver = check_versioning(s3, b)
        bpa = check_block_public_access(s3, b)
        pol = check_bucket_policy_public(s3, b)
        acl = check_bucket_acl_public(s3, b)
        results.append({
            "provider": "aws", "bucket_name": b, "scan_time": ts,
            "block_public_access": bpa,
            "effective_public_read": (pol["effective_public_read"] or acl) and not bpa,
            "effective_public_write": pol["effective_public_write"] and not bpa,
            "encryption_enabled": enc, "logging_enabled": log, "versioning_enabled": ver,
            "wildcard_principal": pol["wildcard_principal"], "public_acl_detected": acl,
            "overly_permissive_iam": [], "raw_evidence": f"Policy: {pol['raw_policy']} | ACL: {acl}"
        })
    return results

def _run_gcp(project_id, cred_json):
    from gcp.gcp_scanner import scan_gcp_storage_buckets
    tmp = None
    if cred_json:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(cred_json)
            tmp = f.name
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = tmp
    try:
        return scan_gcp_storage_buckets(project_id=project_id or None)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
            os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)

def _analyze(raw):
    from engine.processor import process_scans
    return process_scans(raw)


# Session defaults
for k, v in {"tab": "scan", "prov": "AWS", "raw": [], "analysis": [], "error": None}.items():
    if k not in st.session_state:
        st.session_state[k] = v


# Sidebar Navigation
with st.sidebar:
    st.markdown("""
    <div style="padding:16px 0 20px 0;border-bottom:1px solid #522C5D;margin-bottom:16px;">
        <div style="font-size:15px;font-weight:700;color:#FFE3DE;">Cloud Security Scanner</div>
        <div style="font-size:11px;color:#845162;">Multi-Cloud Storage CIS Auditor</div>
    </div>
    """, unsafe_allow_html=True)

    tabs = [("Auditor Console", "scan"), ("Findings Dashboard", "results"), ("Audit Ledger", "history"), ("Upload JSON", "upload")]
    for lbl, key in tabs:
        if st.button(lbl, key=f"nav_{key}", use_container_width=True):
            st.session_state.tab = key
            st.rerun()

    st.markdown("---")
    st.caption("🔒 All credentials evaluated in-memory only.")


# Header
st.markdown("""
<div style="padding-bottom:16px;border-bottom:1px solid #522C5D;margin-bottom:24px;">
    <div style="display:flex;align-items:center;justify-content:space-between;">
        <div>
            <h1 style="font-size:22px;font-weight:700;color:#FFE3DE;margin:0;">Cloud Storage Security Console</h1>
            <p style="font-size:12px;color:#845162;margin:3px 0 0 0;">CIS compliance evaluation for Amazon S3 and Google Cloud Storage</p>
        </div>
        <span style="font-size:11px;font-weight:600;padding:4px 10px;border-radius:6px;background:#29104A;border:1px solid #522C5D;color:#E3B8B1;">
            CIS v1.0 Standard
        </span>
    </div>
</div>
""", unsafe_allow_html=True)


# TAB 1: SCANNER
if st.session_state.tab == "scan":
    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        if st.button("AWS S3", use_container_width=True):
            st.session_state.prov = "AWS"
            st.rerun()
    with c2:
        if st.button("GCP GCS", use_container_width=True):
            st.session_state.prov = "GCP"
            st.rerun()

    st.markdown(f"**Target Service:** `{st.session_state.prov}`")

    if st.session_state.prov == "AWS":
        with st.form("aws_form"):
            col_a, col_b = st.columns(2)
            with col_a:
                key_id = st.text_input("AWS Access Key ID", placeholder="AKIAIOSFODNN7EXAMPLE")
                token = st.text_input("AWS Session Token (Optional)", type="password", placeholder="For STS / SSO credentials")
            with col_b:
                secret = st.text_input("AWS Secret Access Key", type="password", placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
                region = st.selectbox("AWS Region", ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1"])

            run_aws_btn = st.form_submit_button("Initiate AWS Security Audit", type="primary", use_container_width=True)

        if run_aws_btn:
            with st.spinner("Connecting to AWS S3 and auditing security posture..."):
                try:
                    raw = _run_aws(key_id, secret, token, region)
                    st.session_state.raw = raw
                    st.session_state.analysis = _analyze(raw)
                    st.session_state.tab = "results"
                    st.rerun()
                except Exception as e:
                    st.error(f"Scan failed: {e}")

    else:
        with st.form("gcp_form"):
            project_id = st.text_input("Google Cloud Project ID", placeholder="my-gcp-project-12345")
            sa_json = st.text_area("Service Account Key JSON", placeholder='{\n  "type": "service_account",\n  "project_id": "...",\n  ...\n}')
            run_gcp_btn = st.form_submit_button("Initiate GCP Security Audit", type="primary", use_container_width=True)

        if run_gcp_btn:
            with st.spinner("Connecting to GCP Storage and auditing security posture..."):
                try:
                    raw = _run_gcp(project_id, sa_json)
                    st.session_state.raw = raw
                    st.session_state.analysis = _analyze(raw)
                    st.session_state.tab = "results"
                    st.rerun()
                except Exception as e:
                    st.error(f"Scan failed: {e}")


# TAB 2: FINDINGS
elif st.session_state.tab == "results":
    if not st.session_state.analysis:
        st.info("No scan findings in current session. Run a scan from the Auditor Console.")
    else:
        analysis = st.session_state.analysis
        total = len(analysis)
        crit = sum(1 for r in analysis if r.get("severity") == "critical")
        high = sum(1 for r in analysis if r.get("severity") == "high")
        avg = int(sum(r.get("risk_score", 0) for r in analysis) / total) if total else 0

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f'<div class="metric-box"><div class="val">{total}</div><div class="lbl">Audited Buckets</div></div>', unsafe_allow_html=True)
        with m2:
            st.markdown(f'<div class="metric-box"><div class="val">{avg}</div><div class="lbl">Avg Risk Index</div></div>', unsafe_allow_html=True)
        with m3:
            st.markdown(f'<div class="metric-box"><div class="val">{crit}</div><div class="lbl">Critical Risks</div></div>', unsafe_allow_html=True)
        with m4:
            st.markdown(f'<div class="metric-box"><div class="val">{high}</div><div class="lbl">High Severity</div></div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        for b in analysis:
            bname = b["bucket_name"]
            score = b["risk_score"]
            sev = b["severity"].upper()

            with st.expander(f"{bname}   ·   Risk Score: {score}/100   ·   [{sev}]"):
                col_x, col_y = st.columns([1, 1])
                with col_x:
                    st.markdown("**CIS Benchmark Findings:**")
                    if not b.get("findings"):
                        st.success("Bucket conforms to all baseline CIS controls.")
                    else:
                        for f in b.get("findings", []):
                            st.markdown(f"- **CIS {f.get('cis_control')}**: `{f.get('id')}` ({f.get('explanation_key')})")
                with col_y:
                    st.markdown("**Drift & History:**")
                    drift = b.get("drift", {})
                    if drift.get("changed"):
                        st.warning(f"Drift Detected: {drift.get('change')}")
                    else:
                        st.write("No configuration drift recorded.")


# TAB 3: HISTORY
elif st.session_state.tab == "history":
    import sqlite3, pandas as pd
    db_path = os.path.join(ROOT, "scans.db")
    if os.path.exists(db_path):
        with sqlite3.connect(db_path) as conn:
            df = pd.read_sql_query("SELECT bucket_name, provider, scan_time, risk_score, severity, effective_public_read FROM scan_history ORDER BY id DESC LIMIT 200", conn)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No SQLite scan history database found.")


# TAB 4: UPLOAD
elif st.session_state.tab == "upload":
    uploaded = st.file_uploader("Upload Saved Scan Output (JSON)", type=["json"])
    if uploaded:
        data = json.load(uploaded)
        st.session_state.raw = data
        st.session_state.analysis = _analyze(data)
        st.session_state.tab = "results"
        st.rerun()
