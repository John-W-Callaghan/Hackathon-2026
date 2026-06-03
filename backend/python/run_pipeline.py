"""
run_pipeline.py — Node.js → Python bridge

Reads asset names from stdin (one per line), runs the full CVE pipeline,
and prints a single JSON object to stdout. All diagnostic output from the
pipeline is redirected to stderr so stdout remains a clean JSON contract.
"""

import json
import sys
import os

# Redirect stdout temporarily so pipeline print() calls go to stderr
_real_stdout = sys.stdout
sys.stdout = sys.stderr

# Add project root to path so imports resolve correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from matcher import load_cve_records, build_asset_cpe_map, match_cves
from epss_loader import epss_raw
from normalisation import KEV_PATH
import json as _json

# Restore stdout for our final JSON output
sys.stdout = _real_stdout


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


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print(json.dumps({"results": [], "unmatched": []}))
        return

    assets = [line.strip() for line in raw.splitlines() if line.strip()]

    # Load data (diagnostic output goes to stderr via the redirect above)
    records = load_cve_records()

    with open(KEV_PATH, encoding="utf-8") as fh:
        kev_data = _json.load(fh)
    kev_set = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}

    asset_cpe_map = build_asset_cpe_map(assets)
    unmatched = [a for a in assets if a not in asset_cpe_map]

    matches = match_cves(records, asset_cpe_map, kev_set=kev_set, epss_dict=epss_raw)
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

    print(json.dumps({"results": results, "unmatched": unmatched}))


if __name__ == "__main__":
    main()
