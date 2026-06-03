"""
load_kev.py — Download and parse the CISA Known Exploited Vulnerabilities (KEV) catalog.
Uses only the Python standard library.
"""

import json
import urllib.request
import urllib.error
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
LOCAL_FILE = Path("known_exploited_vulnerabilities.json")
SANITY_CVE = "CVE-2021-44228"  # Log4Shell — well-known entry for sanity checking


# ---------------------------------------------------------------------------
# Step 1: Download the KEV JSON from CISA and save it locally
# ---------------------------------------------------------------------------

def download_kev(url: str, dest: Path) -> None:
    """Fetch the KEV catalog over HTTPS and write the raw bytes to disk."""
    print(f"Downloading KEV catalog from:\n  {url}")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        # Server returned a non-2xx status (e.g. 404, 503)
        raise SystemExit(f"HTTP error {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        # DNS failure, connection refused, timeout, etc.
        raise SystemExit(f"Network error: {exc.reason}") from exc

    dest.write_bytes(raw)
    print(f"Saved → {dest}  ({len(raw):,} bytes)\n")


# ---------------------------------------------------------------------------
# Step 2: Load and parse the saved JSON file
# ---------------------------------------------------------------------------

def load_vulnerabilities(path: Path) -> list[dict]:
    """Read the local JSON file and return the list of vulnerability records."""
    if not path.exists():
        raise SystemExit(f"File not found: {path}  (run without --skip-download first)")

    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Malformed JSON in {path}: {exc}") from exc

    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise SystemExit("Unexpected format: 'vulnerabilities' key is missing or not a list")

    return vulns


# ---------------------------------------------------------------------------
# Step 3: Build the two lookup data structures
# ---------------------------------------------------------------------------

def build_lookup_structures(vulns: list[dict]) -> tuple[set, dict]:
    """
    Returns:
      kev_set  — set of cveID strings for fast O(1) membership tests
      kev_dict — dict keyed by cveID → full vulnerability record
    """
    # Set comprehension: just the CVE IDs
    kev_set = {entry["cveID"] for entry in vulns}

    # Dict comprehension: CVE ID → complete record
    kev_dict = {entry["cveID"]: entry for entry in vulns}

    return kev_set, kev_dict


# ---------------------------------------------------------------------------
# Step 4: Print confirmation output
# ---------------------------------------------------------------------------

def print_summary(vulns: list[dict], kev_set: set) -> None:
    """Display total count, the 3 newest entries, and a Log4Shell sanity check."""

    print(f"Total KEV entries loaded: {len(vulns):,}")

    # Sort all entries descending by dateAdded (ISO-8601 strings sort correctly as text)
    recent_three = sorted(vulns, key=lambda e: e.get("dateAdded", ""), reverse=True)[:3]

    print("\n3 most recently added entries:")
    print(f"  {'dateAdded':<12}  {'cveID':<20}  {'vendorProject':<25}  product")
    print(f"  {'-'*10}  {'-'*18}  {'-'*23}  -------")
    for entry in recent_three:
        print(
            f"  {entry.get('dateAdded', 'N/A'):<12}  "
            f"{entry.get('cveID', 'N/A'):<20}  "
            f"{entry.get('vendorProject', 'N/A'):<25}  "
            f"{entry.get('product', 'N/A')}"
        )

    # Sanity check: Log4Shell (CVE-2021-44228) must be in the catalog
    found = SANITY_CVE in kev_set
    print(f"\nSanity check — {SANITY_CVE} (Log4Shell) in kev_set: {'YES ✓' if found else 'NO ✗ (unexpected!)'}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # Download only when the file isn't already present locally,
    # so re-runs work offline without re-fetching each time.
    if LOCAL_FILE.exists():
        print(f"{LOCAL_FILE} already exists — skipping download. Delete it to re-fetch.\n")
    else:
        download_kev(KEV_URL, LOCAL_FILE)

    # Parse the local file into a list of dicts
    vulns = load_vulnerabilities(LOCAL_FILE)

    # Build fast-lookup structures
    kev_set, kev_dict = build_lookup_structures(vulns)

    # Print confirmation
    print_summary(vulns, kev_set)


if __name__ == "__main__":
    main()
