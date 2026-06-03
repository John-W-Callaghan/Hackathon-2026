"""
load_cve.py — Parse NVD CVE JSON data files (fkie-cad/nvd-json-data-feeds format).
Uses only the Python standard library.
"""

import json
from pathlib import Path

CVE_DIR     = Path(__file__).parent.parent / "dataset" / "NVD-CVE"
DEFAULT_YEAR = 2024
SANITY_CVE  = "CVE-2024-21762"  # FortiOS — high-profile 2024 CVE for sanity checking


# ---------------------------------------------------------------------------
# Step 1: Load and parse the CVE JSON file
# ---------------------------------------------------------------------------

def load_cve_records(path: Path) -> list[dict]:
    """Read a local NVD CVE JSON file and return the flat list of CVE records."""
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    print(f"Loading CVE records from {path} …")
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Malformed JSON in {path}: {exc}") from exc

    records = data.get("cve_items")
    if not isinstance(records, list):
        raise SystemExit("Unexpected format: 'cve_items' key is missing or not a list")

    print(f"  Loaded {len(records):,} CVE records.\n")
    return records


# ---------------------------------------------------------------------------
# Step 2: Build a fast-lookup index
# ---------------------------------------------------------------------------

def build_cve_index(records: list[dict]) -> dict[str, dict]:
    """Return { cve_id: full_record } for O(1) lookups by CVE ID."""
    return {record["id"]: record for record in records}


# ---------------------------------------------------------------------------
# Step 3: Print confirmation output
# ---------------------------------------------------------------------------

def print_summary(records: list[dict], cve_index: dict[str, dict]) -> None:
    """Display total count, the 5 most recently published entries, and a sanity check."""
    print(f"Total CVE records loaded: {len(records):,}")

    recent_five = sorted(
        records, key=lambda r: r.get("published", ""), reverse=True
    )[:5]

    print("\n5 most recently published CVEs:")
    print(f"  {'published':<12}  {'cveID':<20}  description (first 60 chars)")
    print(f"  {'-'*10}  {'-'*18}  {'-'*60}")
    for r in recent_five:
        desc = next(
            (d["value"] for d in r.get("descriptions", []) if d["lang"] == "en"),
            "No description",
        )
        print(f"  {r.get('published', 'N/A')[:10]:<12}  {r.get('id', 'N/A'):<20}  {desc[:60]}")

    found = SANITY_CVE in cve_index
    status = "YES ✓" if found else "NO ✗ (may not be in this year file)"
    print(f"\nSanity check — {SANITY_CVE} in index: {status}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    path = CVE_DIR / f"CVE-{DEFAULT_YEAR}.json"
    records = load_cve_records(path)
    cve_index = build_cve_index(records)
    print_summary(records, cve_index)


if __name__ == "__main__":
    main()
