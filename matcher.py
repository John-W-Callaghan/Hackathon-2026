"""
matcher.py — CVE matching stage (Hour 3)

Pipeline:  normalisation.py → [matcher.py] → ranker.py

Resolves each asset name to CPE fragments, scans all CVE records
for those fragments, and returns an enriched list of matches ready for
ranking in Hour 4.

Standalone: works without KEV/EPSS.  Pass kev_set and epss_dict once
teammates have their loaders ready (see match_cves signature below).
"""

import json
from collections import Counter
from pathlib import Path

from normalisation import normalise, KEV_PATH

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CVE_DIR = Path(__file__).parent / "dataset" / "NVD-CVE"

# ---------------------------------------------------------------------------
# Sample asset list (12 entries from the project brief)
# ---------------------------------------------------------------------------

SAMPLE_ASSETS = [
    "Microsoft 365 Apps for Business",
    "Windows Server 2022",
    "Windows 10 Pro",
    "Adobe Acrobat Reader DC",
    "Cisco IOS XE",
    "VMware vSphere",
    "Google Chrome",
    "OpenSSL",
    "Apache HTTP Server",
    "Zoom",
    "WordPress",
    "Moodle",
]


# ---------------------------------------------------------------------------
# Stage 1: Load CVE records
# ---------------------------------------------------------------------------

def load_cve_records(directory: Path = CVE_DIR) -> list[dict]:
    """
    Load all CVE-YYYY.json files found in directory and return the combined
    list of records. Files are processed in filename order (2024 before 2025).
    """
    cve_files = sorted(directory.glob("CVE-*.json"))
    if not cve_files:
        raise SystemExit(f"No CVE JSON files found in {directory}")

    all_records: list[dict] = []
    for path in cve_files:
        print(f"Loading CVE records from {path} ...")
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        records = data["cve_items"]
        print(f"  Loaded {len(records):,} records.")
        all_records.extend(records)

    print(f"  Total: {len(all_records):,} CVE records across {len(cve_files)} file(s).\n")
    return all_records


# ---------------------------------------------------------------------------
# Stage 2: Per-record extraction helpers
# ---------------------------------------------------------------------------

def extract_cpe_strings(record: dict) -> list[str]:
    """
    Return all CPE criteria strings from a CVE's configurations block.
    Structure: configurations → nodes → cpeMatch → criteria
    """
    cpe_strings = []
    for node in record.get("configurations", []):
        for subnode in node.get("nodes", []):
            for match in subnode.get("cpeMatch", []):
                cpe_strings.append(match["criteria"])
    return cpe_strings


def _cpe_vendor_product(cpe_string: str) -> str:
    """
    Extract the vendor:product portion from a full CPE 2.3 string.

    CPE format: cpe:2.3:<type>:<vendor>:<product>:<version>:...
    Index:          0   1    2       3        4         5

    Returns "vendor:product", or "" if the string is malformed.
    """
    parts = cpe_string.split(":")
    if len(parts) >= 5:
        return f"{parts[3]}:{parts[4]}"
    return ""


def extract_cvss(record: dict) -> float | None:
    """Return the highest-version CVSS base score available, or None."""
    metrics = record.get("metrics", {})
    if "cvssMetricV31" in metrics:
        return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    if "cvssMetricV30" in metrics:
        return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    if "cvssMetricV2" in metrics:
        return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    return None


def extract_description(record: dict) -> str:
    """Return the English description string, or an empty string."""
    descs = record.get("descriptions", [])
    return next((d["value"] for d in descs if d["lang"] == "en"), "")


# ---------------------------------------------------------------------------
# Stage 3: Normalise assets → CPE fragment map
# ---------------------------------------------------------------------------

def build_asset_cpe_map(assets: list[str]) -> dict[str, list[str]]:
    """
    Return { asset_name: [cpe_fragment, ...] } for every asset that resolves.
    Assets with no CPE match are excluded; normalise() already prints a
    WARNING for each one, so unmatched assets are never silent.
    """
    print("=== Normalising assets ===")
    asset_map: dict[str, list[str]] = {}
    unmatched: list[str] = []

    for asset in assets:
        fragments = normalise(asset)
        if fragments:
            asset_map[asset] = fragments
        else:
            unmatched.append(asset)

    print(f"\n  {len(asset_map)} assets resolved, {len(unmatched)} unmatched.")
    if unmatched:
        print(f"  Unmatched (no CVEs will be returned): {unmatched}")
    print()
    return asset_map


# ---------------------------------------------------------------------------
# Stage 4: Match CVE records against asset CPE fragments
# ---------------------------------------------------------------------------

def match_cves(
    records: list[dict],
    asset_cpe_map: dict[str, list[str]],
    kev_set: set | None = None,
    epss_dict: dict | None = None,
) -> list[dict]:
    """
    Scan every CVE record and return one dict per CVE-asset hit.

    CPE matching uses substring containment:
      "openssl:openssl" in "cpe:2.3:a:openssl:openssl:3.0.7:..."  → True

    Parameters
    ----------
    records       : output of load_cve_records()
    asset_cpe_map : output of build_asset_cpe_map()
    kev_set       : set of CVE ID strings from CISA KEV (teammate supplies)
    epss_dict     : { cve_id: float } EPSS probability (teammate supplies)

    Returns
    -------
    List of dicts with keys:
      cve_id, asset, description, cvss_score, epss_score, in_kev
    """
    kev_set = kev_set or set()
    epss_dict = epss_dict or {}

    print(
        f"=== Matching {len(asset_cpe_map)} assets against "
        f"{len(records):,} CVE records ==="
    )

    matches: list[dict] = []

    for record in records:
        cve_id = record["id"]
        cpe_strings = extract_cpe_strings(record)

        if not cpe_strings:
            # Record has no CPE applicability data — nothing to match on
            continue

        for asset, fragments in asset_cpe_map.items():
            # Exact vendor:product match — avoids substring false positives
            # e.g. "windows_server_2022" must not match "windows_server_2022_23h2"
            hit = any(
                fragment == _cpe_vendor_product(cpe)
                for fragment in fragments
                for cpe in cpe_strings
            )

            if hit:
                matches.append({
                    "cve_id":      cve_id,
                    "asset":       asset,
                    "description": extract_description(record),
                    "cvss_score":  extract_cvss(record),
                    "epss_score":  epss_dict.get(cve_id, 0.0),
                    "in_kev":      cve_id in kev_set,
                })

    print(f"  Found {len(matches):,} CVE-asset matches.\n")
    return matches


# ---------------------------------------------------------------------------
# Stage 5: Match summary (diagnostic — remove or suppress before final demo)
# ---------------------------------------------------------------------------

def print_match_summary(matches: list[dict]) -> None:
    """Print match counts per asset, sorted descending."""
    counts = Counter(m["asset"] for m in matches)
    print("=== Match summary by asset ===")
    for asset, count in counts.most_common():
        print(f"  {asset:<45s} {count:>4} CVEs")
    print()


# ---------------------------------------------------------------------------
# Main — standalone run; teammates call match_cves() with their data later
# ---------------------------------------------------------------------------

def main(assets: list[str] | None = None) -> list[dict]:
    # Stage 1: Load CVE records
    records = load_cve_records()

    # Stage 2: Resolve asset names → CPE fragments
    asset_cpe_map = build_asset_cpe_map(assets or SAMPLE_ASSETS)

    # Load KEV — read directly from local JSON, no network call
    with KEV_PATH.open(encoding="utf-8") as fh:
        kev_data = json.load(fh)
    kev_set = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
    print(f"  Loaded {len(kev_set):,} KEV entries.\n")

    # Load EPSS — epss_loader populates epss_raw at import time
    from epss_loader import epss_raw as epss_dict
    print(f"  Loaded {len(epss_dict):,} EPSS scores.\n")

    # Match with full enrichment
    matches = match_cves(records, asset_cpe_map, kev_set=kev_set, epss_dict=epss_dict)

    # Stage 4: Diagnostic summary
    print_match_summary(matches)

    # Stage 5: Preview the first few rows
    print("=== Sample rows (first 5) ===")
    for m in matches[:5]:
        print(
            f"  {m['cve_id']}  asset={m['asset']!r}  "
            f"cvss={m['cvss_score']}  epss={m['epss_score']:.4f}  kev={m['in_kev']}"
        )
        print(f"    {m['description'][:120]}")
    print()

    # Return the list so ranker.py can import and call main() directly,
    # or teammates can call match_cves() with their enrichment data.
    return matches


if __name__ == "__main__":
    main()
