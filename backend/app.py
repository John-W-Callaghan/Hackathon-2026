"""
Flask backend for the CVE-to-My-Stack Translator.

Replaces the previous Express/Node bridge — runs the pipeline in-process
instead of spawning a Python subprocess.
"""

import json
import os
import sys

from flask import Flask, jsonify, request
from flask_cors import CORS

# Add project root to path so pipeline modules import correctly
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from download_datasets import ensure_datasets
ensure_datasets()

from matcher import load_cve_records, build_asset_cpe_map, match_cves
from epss_loader import epss_raw
from normalisation import KEV_PATH

app = Flask(__name__)
CORS(app)

# Loaded once at startup and reused across requests
_records = load_cve_records()

with open(KEV_PATH, encoding="utf-8") as fh:
    _kev_data = json.load(fh)
_kev_set = {v["cveID"] for v in _kev_data.get("vulnerabilities", [])}


def rank(matches: list[dict]) -> list[dict]:
    """Sort by: KEV first, then EPSS descending."""
    return sorted(matches, key=lambda m: (not m["in_kev"], -(m["epss_score"] or 0)))


def risk_sentence(m: dict) -> str:
    epss = m["epss_score"] or 0
    if epss >= 0.7:
        prob = "high"
    elif epss >= 0.3:
        prob = "moderate"
    else:
        prob = "low"

    kev_note = (
        "Actively exploited in the wild (CISA KEV)."
        if m["in_kev"]
        else "Not confirmed exploited in the wild."
    )

    return (
        f"{m['cve_id']} affects {m['asset']}. "
        f"EPSS score {epss:.2f} indicates {prob} exploitation probability. "
        f"{kev_note}"
    )


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/scan")
def scan():
    body = request.get_json(silent=True) or {}
    assets = body.get("assets")

    if not isinstance(assets, list) or len(assets) == 0:
        return jsonify({"error": "assets must be a non-empty array"}), 400

    assets = [a.strip() for a in assets if isinstance(a, str) and a.strip()]
    if not assets:
        return jsonify({"error": "assets must be a non-empty array"}), 400

    asset_cpe_map = build_asset_cpe_map(assets)
    unmatched = [a for a in assets if a not in asset_cpe_map]

    matches = match_cves(_records, asset_cpe_map, kev_set=_kev_set, epss_dict=epss_raw)
    ranked = rank(matches)

    results = []
    for m in ranked:
        results.append({
            "cve_id":           m["cve_id"],
            "asset":            m["asset"],
            "cvss_score":       m["cvss_score"],
            "epss_score":       round(m["epss_score"], 4) if m["epss_score"] else 0.0,
            "in_kev":           m["in_kev"],
            "description":      m["description"],
            "risk_description": risk_sentence(m),
        })

    return jsonify({"results": results, "unmatched": unmatched})


if __name__ == "__main__":
    app.run(port=3001, debug=True)
