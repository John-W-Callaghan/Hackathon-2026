"""
ranker.py — Ranking and output stage (Hour 4)

Pipeline:  matcher.py → [ranker.py]

Accepts the list of CVE-asset matches from matcher.py, sorts them with KEV
entries first then by EPSS descending, attaches a plain-English risk sentence,
writes a CSV report, and prints a console summary table.
"""

import argparse
import csv
from pathlib import Path

OUTPUT_CSV = Path(__file__).parent / "cve_report.csv"

CSV_FIELDS = [
    "cve_id",
    "asset",
    "cvss_score",
    "epss_score",
    "in_kev",
    "risk_description",
]


# ---------------------------------------------------------------------------
# Risk sentence helpers
# ---------------------------------------------------------------------------

def _epss_label(epss: float) -> str:
    if epss >= 0.10:
        return "high"
    if epss >= 0.01:
        return "moderate"
    return "low"


def build_risk_sentence(match: dict) -> str:
    """Return a one-sentence plain-English risk summary for a CVE-asset pair."""
    epss = match["epss_score"] or 0.0
    kev_clause = (
        "Actively exploited in the wild (CISA KEV confirmed)."
        if match["in_kev"]
        else "Not confirmed exploited in the wild."
    )
    return (
        f"CVE {match['cve_id']} affects {match['asset']}. "
        f"EPSS score {epss:.4f} indicates {_epss_label(epss)} exploitation probability. "
        f"{kev_clause}"
    )


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

def rank(matches: list[dict]) -> list[dict]:
    """
    Attach risk_description to each match, then sort:
      1. KEV entries first (in_kev=True before False)
      2. EPSS score descending within each group
    """
    for m in matches:
        m["risk_description"] = build_risk_sentence(m)

    return sorted(
        matches,
        key=lambda m: (not m["in_kev"], -(m["epss_score"] or 0.0)),
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_csv(ranked: list[dict], path: Path = OUTPUT_CSV) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(ranked)
    print(f"Report written → {path}  ({len(ranked):,} rows)\n")


def print_table(ranked: list[dict], max_rows: int = 20) -> None:
    """Print a fixed-width summary table to stdout."""
    col_widths = {"cve": 20, "asset": 32, "cvss": 5, "epss": 7, "kev": 5}
    header = (
        f"{'CVE ID':<{col_widths['cve']}} "
        f"{'Asset':<{col_widths['asset']}} "
        f"{'CVSS':>{col_widths['cvss']}} "
        f"{'EPSS':>{col_widths['epss']}} "
        f"{'KEV':<{col_widths['kev']}} "
        f"Risk description"
    )
    separator = "-" * 115

    print("=== CVE Risk Report ===")
    print(header)
    print(separator)

    for m in ranked[:max_rows]:
        kev_flag = "*** YES" if m["in_kev"] else "no"
        cvss = f"{m['cvss_score']:.1f}" if m["cvss_score"] is not None else "N/A"
        epss = f"{m['epss_score']:.4f}" if m["epss_score"] is not None else "N/A"
        asset_short = m["asset"][:col_widths["asset"]]
        risk_short  = m["risk_description"][:55]
        print(
            f"{m['cve_id']:<{col_widths['cve']}} "
            f"{asset_short:<{col_widths['asset']}} "
            f"{cvss:>{col_widths['cvss']}} "
            f"{epss:>{col_widths['epss']}} "
            f"{kev_flag:<{col_widths['kev']}} "
            f"{risk_short}"
        )

    if len(ranked) > max_rows:
        print(f"\n  ... {len(ranked) - max_rows:,} more rows written to {OUTPUT_CSV.name}")
    print()


# ---------------------------------------------------------------------------
# Stats summary
# ---------------------------------------------------------------------------

def print_stats(ranked: list[dict]) -> None:
    total   = len(ranked)
    kev     = sum(1 for m in ranked if m["in_kev"])
    high    = sum(1 for m in ranked if (m["epss_score"] or 0) >= 0.10)
    moderate = sum(1 for m in ranked if 0.01 <= (m["epss_score"] or 0) < 0.10)
    low     = total - high - moderate

    print("=== Summary ===")
    print(f"  Total CVE-asset matches : {total:,}")
    print(f"  In CISA KEV             : {kev:,}  ← prioritise these immediately")
    print(f"  EPSS high  (≥10%)       : {high:,}")
    print(f"  EPSS moderate (1–10%)   : {moderate:,}")
    print(f"  EPSS low   (<1%)        : {low:,}")
    print()


# ---------------------------------------------------------------------------
# Main — can be run standalone or called by a future pipeline entry point
# ---------------------------------------------------------------------------

def _read_asset_file(path: Path) -> list[str]:
    """Read one asset name per non-blank, non-comment line."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def main(matches: list[dict] | None = None, assets: list[str] | None = None) -> list[dict]:
    """
    Rank and output CVE matches.

    If matches is None, runs the full upstream pipeline (matcher.py → main())
    to produce them.  Pass a pre-built list to skip the upstream stages.
    Pass assets to override the default hardcoded asset list.
    """
    if matches is None:
        from matcher import main as run_matcher
        matches = run_matcher(assets=assets)

    if not matches:
        print("No matches to rank — check that CVE data and asset list are loaded.")
        return []

    ranked = rank(matches)
    write_csv(ranked)
    print_table(ranked)
    print_stats(ranked)
    return ranked


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CVE-to-My-Stack Translator — scan your assets for known vulnerabilities."
    )
    parser.add_argument(
        "assets",
        nargs="?",
        help="Path to a plain-text asset list file (one product per line). "
             "Defaults to the built-in sample list if omitted.",
    )
    args = parser.parse_args()

    asset_list = None
    if args.assets:
        asset_path = Path(args.assets)
        asset_list = _read_asset_file(asset_path)
        print(f"Loaded {len(asset_list)} assets from {asset_path}\n")

    main(assets=asset_list)
