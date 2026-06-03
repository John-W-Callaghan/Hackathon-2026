"""
EPSS Score Loader & Normaliser
Loads epss_scores-2026-05-19_csv.gz into Python dicts and normalises scores.

Dicts produced:
  epss_raw        : { cve_id -> float }   raw EPSS probability (0–1)
  epss_percentile : { cve_id -> float }   pre-computed percentile (0–1)
  epss_normalised : { cve_id -> float }   min-max normalised EPSS score (0–1)
  epss_combined   : { cve_id -> dict }    all three values per CVE
"""

import csv        # for parsing the CSV rows inside the gz file
import gzip       # for opening the compressed .gz file
from pathlib import Path  # cleaner cross-platform file path handling


# Path to the EPSS data file — update this if your file is elsewhere
FILE_PATH = Path("epss_scores-2026-05-19_csv.gz")


def load_epss(path: Path) -> tuple[dict, dict]:
    """
    Open the gzipped CSV and read every row into two dicts.

    The file has a non-standard first line starting with '#' that holds
    metadata (model version, score date). We read and discard that manually
    before handing the rest to csv.DictReader.

    Returns:
        raw        -- { cve_id: epss_score }   e.g. {"CVE-1999-0001": 0.0119}
        percentile -- { cve_id: percentile }   e.g. {"CVE-1999-0001": 0.79034}
    """
    # Two empty dicts — we'll populate these as we loop through the file
    raw: dict[str, float] = {}
    percentile: dict[str, float] = {}

    # gzip.open with "rt" decodes the bytes to a normal text stream
    with gzip.open(path, "rt", newline="") as f:

        # Manually read the first line so csv.DictReader doesn't see it
        first = f.readline()
        if not first.startswith("#"):
            # Sanity check — if the format ever changes we want a clear error
            raise ValueError(f"Expected comment line, got: {first!r}")

        # DictReader uses the next line (cve,epss,percentile) as column headers
        # and then yields each subsequent row as a dict automatically
        reader = csv.DictReader(f)
        for row in reader:
            cve = row["cve"]                        # e.g. "CVE-1999-0001"
            raw[cve] = float(row["epss"])           # str -> float
            percentile[cve] = float(row["percentile"])

    return raw, percentile


def normalise_minmax(scores: dict[str, float]) -> dict[str, float]:
    """
    Apply min-max normalisation to scale all scores into the range [0, 1].

    Formula for each value:
        normalised = (value - min) / (max - min)

    This means the lowest score in the dataset becomes 0.0 and the highest
    becomes 1.0, with everything else scaled proportionally in between.

    The edge case where all values are identical (span == 0) would cause a
    division by zero, so we return 0.0 for everything in that scenario.
    """
    values = scores.values()
    lo = min(values)   # smallest EPSS score in the whole dataset
    hi = max(values)   # largest EPSS score in the whole dataset
    span = hi - lo     # total range — used as the denominator

    # Guard against division by zero if every score is the same
    if span == 0:
        return {k: 0.0 for k in scores}

    # Dict comprehension: apply the formula to every key-value pair at once
    # scores.items() gives us (cve_id, score) pairs to loop over
    return {k: (v - lo) / span for k, v in scores.items()}


def build_combined(
    raw: dict[str, float],
    percentile: dict[str, float],
    normalised: dict[str, float],
) -> dict[str, dict]:
    """
    Merge the three separate dicts into one dict-of-dicts, keyed by CVE ID.

    This is handy if you want to look up everything about a CVE in one go
    rather than hitting three separate dicts.

    Example output entry:
        "CVE-1999-0003": {
            "epss":           0.90626,
            "percentile":     0.99629,
            "epss_normalised": 0.95880,
        }
    """
    # Dict comprehension iterating over all CVE IDs from the raw dict
    # We assume all three dicts have the same keys (they will, since
    # normalised is derived from raw, and percentile was loaded alongside it)
    return {
        cve: {
            "epss": raw[cve],
            "percentile": percentile[cve],
            "epss_normalised": normalised[cve],
        }
        for cve in raw
    }


# ── Main ─────────────────────────────────────────────────────────────────────
# This runs top-to-bottom when you execute the script directly.
# The three function calls below build all four dicts in sequence.

epss_raw, epss_percentile = load_epss(FILE_PATH)   # load raw data from file
epss_normalised = normalise_minmax(epss_raw)        # normalise the EPSS scores
epss_combined = build_combined(                     # merge into one dict
    epss_raw, epss_percentile, epss_normalised
)

# ── Quick sanity check ───────────────────────────────────────────────────────
# Print a summary so you can visually confirm the data loaded correctly

print(f"Loaded {len(epss_raw):,} CVEs\n")

# Grab the first 5 CVE IDs to use as a preview sample
sample_cves = list(epss_raw.keys())[:5]

# f-string format spec:  <20 = left-align in 20 chars,  >10 = right-align in 10
print(f"{'CVE':<20}  {'raw EPSS':>10}  {'percentile':>10}  {'normalised':>10}")
print("-" * 58)
for cve in sample_cves:
    print(
        f"{cve:<20}  {epss_raw[cve]:>10.5f}  "
        f"{epss_percentile[cve]:>10.5f}  {epss_normalised[cve]:>10.5f}"
    )

# Convert to lists so we can call min/max (dict_values doesn't support it twice)
raw_vals = list(epss_raw.values())
norm_vals = list(epss_normalised.values())
print(f"\nRaw  EPSS  — min: {min(raw_vals):.5f}  max: {max(raw_vals):.5f}")
print(f"Norm EPSS  — min: {min(norm_vals):.5f}  max: {max(norm_vals):.5f}")

# ── Example lookups ──────────────────────────────────────────────────────────
# Shows how to pull data out of each dict once you have a CVE ID

cve = "CVE-1999-0003"
print(f"\nLookup example — {cve}:")
print(f"  epss_raw[cve]        = {epss_raw[cve]}")
print(f"  epss_percentile[cve] = {epss_percentile[cve]}")
print(f"  epss_normalised[cve] = {epss_normalised[cve]:.6f}")
print(f"  epss_combined[cve]   = {epss_combined[cve]}")  # all three at once
