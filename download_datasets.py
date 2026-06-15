"""
download_datasets.py — Bootstrap the local dataset directory.

Called automatically by backend/app.py on first startup.
Skips any file that already exists locally.

Sources:
  KEV   — cisa.gov public feed
  CVE   — github.com/fkie-cad/nvd-json-data-feeds releases (gzip → JSON)
  EPSS  — epss.cyentia.com daily scores (kept as .csv.gz)
"""

import gzip
import shutil
import sys
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).parent
DATASET = ROOT / "dataset"

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CVE_BASE = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/download/latest/CVE-{year}.json.gz"
)
EPSS_BASE = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"

CVE_YEARS = [2024, 2025, 2026]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch(url: str, dest: Path, label: str) -> bool:
    """Download url to dest, printing progress. Returns True on success."""
    print(f"  Downloading {label} …", end=" ", flush=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            raw = resp.read()
        dest.write_bytes(raw)
        print(f"done ({len(raw) / 1_048_576:.1f} MB)")
        return True
    except urllib.error.HTTPError as exc:
        print(f"FAILED (HTTP {exc.code})")
        return False
    except urllib.error.URLError as exc:
        print(f"FAILED ({exc.reason})")
        return False


def _decompress_gz(src: Path, dest: Path) -> None:
    """Decompress a .gz file to dest, then remove the .gz."""
    with gzip.open(src, "rb") as f_in, dest.open("wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    src.unlink()


# ---------------------------------------------------------------------------
# Per-dataset download functions
# ---------------------------------------------------------------------------

def _download_kev() -> bool:
    dest = DATASET / "CISA-KEV" / "known_exploited_vulnerabilities.json"
    if dest.exists():
        return True
    return _fetch(KEV_URL, dest, "CISA KEV")


def _download_cve(year: int) -> bool:
    dest = DATASET / "NVD-CVE" / f"CVE-{year}.json"
    if dest.exists():
        return True
    gz = dest.with_suffix(".json.gz")
    url = CVE_BASE.format(year=year)
    if not _fetch(url, gz, f"CVE-{year}"):
        return False
    print(f"  Decompressing CVE-{year}.json.gz …", end=" ", flush=True)
    try:
        _decompress_gz(gz, dest)
        print("done")
        return True
    except Exception as exc:
        print(f"FAILED ({exc})")
        gz.unlink(missing_ok=True)
        return False


def _download_epss() -> bool:
    epss_dir = DATASET / "EPSS"
    if any(epss_dir.glob("epss_scores-*.csv.gz")):
        return True

    # Try today then fall back up to 7 days (scores are published with a delay)
    for days_ago in range(8):
        target = date.today() - timedelta(days=days_ago)
        date_str = target.strftime("%Y-%m-%d")
        url = EPSS_BASE.format(date=date_str)
        dest = epss_dir / f"epss_scores-{date_str}.csv.gz"
        if _fetch(url, dest, f"EPSS ({date_str})"):
            return True
        dest.unlink(missing_ok=True)

    return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def ensure_datasets() -> None:
    """Check for missing datasets and download them. Exits on any failure."""
    checks = [
        ("CISA KEV", _download_kev),
        *[(f"NVD CVE {y}", lambda y=y: _download_cve(y)) for y in CVE_YEARS],
        ("EPSS scores", _download_epss),
    ]

    missing = [
        (label, fn)
        for label, fn in checks
        if not _is_present(label)
    ]

    if not missing:
        return

    print("First-run setup: downloading required datasets (this may take a few minutes) …")
    failed = []
    for label, fn in checks:
        if not _is_present(label):
            if not fn():
                failed.append(label)

    if failed:
        print(
            f"\nERROR: Could not download: {', '.join(failed)}\n"
            "Check your internet connection and try again.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("All datasets ready.\n")


def _is_present(label: str) -> bool:
    """Quick existence check without re-running the download function."""
    if label == "CISA KEV":
        return (DATASET / "CISA-KEV" / "known_exploited_vulnerabilities.json").exists()
    if label == "EPSS scores":
        return any((DATASET / "EPSS").glob("epss_scores-*.csv.gz"))
    for year in CVE_YEARS:
        if label == f"NVD CVE {year}":
            return (DATASET / "NVD-CVE" / f"CVE-{year}.json").exists()
    return False


if __name__ == "__main__":
    ensure_datasets()
    print("Dataset bootstrap complete.")
