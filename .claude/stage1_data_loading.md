# Stage 1 — Data Loading (Hour 1)

## Status: Partially complete

---

## What this stage does

Loads all offline data feeds into memory so the rest of the pipeline can operate without
any network calls. Each feed is a separate file with a different format.

---

## Data feeds — current state

| Feed | File | Location | Status |
|------|------|----------|--------|
| CISA KEV | `known_exploited_vulnerabilities.json` | `dataset/CISA-KEV/` | ✅ present and loadable |
| EPSS scores | `epss_scores-2026-05-19.csv.gz` | `dataset/EPSS/` | ✅ present and loadable |
| CPE dictionary | `nvdcpe-2.0-chunk-00001…00016.json` | `dataset/CPE-DICT/` | ✅ present (16 chunks) |
| NVD CVE 2024 | `CVE-2024.json` | `dataset/NVD-CVE/` | ❌ missing |
| NVD CVE 2025 | `CVE-2025.json` | `dataset/NVD-CVE/` | ❌ missing |

---

## Loaders built

### CISA KEV — `dataset scrape/load_kev.py`

Loads the CISA Known Exploited Vulnerabilities catalogue.

Produces two structures:
- `kev_set` — `set[str]` of CVE IDs for fast O(1) membership checks
- `kev_dict` — `dict[str, dict]` of CVE ID → full record for detail lookups

Key function signatures:
```python
load_vulnerabilities(path: Path) -> list[dict]
build_lookup_structures(vulns: list[dict]) -> tuple[set, dict]
```

### EPSS scores — `dataset scrape/epss_loader.py` and `epss_loader.py`

Loads the daily EPSS exploitation probability CSV (gzip-compressed).

The file has a non-standard `#` comment line as its first row — the loader strips this
before handing the rest to `csv.DictReader`.

Produces three structures:
- `epss_raw` — `{ cve_id: float }` raw probability (0–1)
- `epss_percentile` — `{ cve_id: float }` pre-computed percentile (0–1)
- `epss_normalised` — `{ cve_id: float }` min-max scaled score (0–1)
- `epss_combined` — `{ cve_id: dict }` all three values in one lookup

333,997 CVEs loaded from the 2026-05-19 snapshot.

**Path note:** There are two copies of `epss_loader.py`:
- `epss_loader.py` at project root — path: `Path(__file__).parent / "dataset" / "EPSS" / ...`
- `dataset scrape/epss_loader.py` — path: `Path(__file__).parent.parent / "dataset" / "EPSS" / ...`

Both point to the same file. The extra `.parent` is needed because `dataset scrape/` is
one level below the project root.

---

## What is still missing

- `CVE-2024.json` and `CVE-2025.json` — the primary CVE database. The matcher cannot
  run without at least one of these. When they arrive, place them in `dataset/NVD-CVE/`.
- `sample_asset_list.txt` — the facilitator-provided asset list for the demo. Until it
  arrives, `SAMPLE_ASSETS` in `matcher.py` is used as a stand-in.

---

## Path constants (centralised in `normalisation.py`)

```python
DATA_DIR      = Path(__file__).parent / "dataset"
KEV_PATH      = DATA_DIR / "CISA-KEV" / "known_exploited_vulnerabilities.json"
NVD_2024_PATH = DATA_DIR / "NVD-CVE"  / "CVE-2024.json"
NVD_2025_PATH = DATA_DIR / "NVD-CVE"  / "CVE-2025.json"
EPSS_DIR      = DATA_DIR / "EPSS"
EPSS_GLOB     = "epss_scores-*.csv.gz"
```

Use `EPSS_DIR.glob(EPSS_GLOB)` to find the EPSS file regardless of the exact date in
the filename.
