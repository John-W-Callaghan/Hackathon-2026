# Stage 4 — Ranking and Output (Hour 4)

## Status: Not started

---

## Prerequisites before starting Stage 4

- matcher.py bugs are now fixed (missing `build_asset_cpe_map()`, module-level crash lines, wrong `CVE_FILE` path) ✅
- NVD CVE files (`CVE-2024.json` / `CVE-2025.json`) still missing — Stage 4 cannot be fully tested without them ❌
- `epss_loader.py` and `load_kev.py` are both working ✅

---

## What this stage does

Takes the list of CVE-asset matches from Stage 3, applies EPSS scores and KEV flags to
rank them by urgency, generates a plain-English risk sentence per CVE, and writes the
final output to CSV.

This is the last stage before the demo. Output must be readable by a non-expert — a solo
sysadmin should be able to open the CSV and know immediately which CVE to action first.

---

## File to build: `ranker.py`

### Pipeline position

```
matcher.py → [ranker.py] → output.csv
```

---

## Input

`matches` — the list of dicts returned by `matcher.match_cves()`:

```python
{
    "cve_id":      str,
    "asset":       str,
    "description": str,
    "cvss_score":  float | None,
    "epss_score":  float,
    "in_kev":      bool,
}
```

---

## Ranking logic

Sort the matches in this priority order:

1. **KEV entries first** — `in_kev=True` always surfaces at the top regardless of EPSS.
   These are confirmed exploited in the wild. A sysadmin must patch these today.
2. **EPSS descending** — within each group (KEV / non-KEV), sort by `epss_score` highest
   to lowest. Higher EPSS = higher probability of exploitation in the next 30 days.

```python
matches.sort(key=lambda m: (not m["in_kev"], -m["epss_score"]))
```

---

## Risk sentence generation

Each row needs a `risk_description` — one plain-English sentence a non-expert can act on.
No jargon. No CVE IDs in the sentence. No score numbers without context.

Pattern:

```
{Severity word} risk to {asset} — {what it allows} — {action}.
```

Examples:
```
Critical risk to Adobe Acrobat Reader DC — allows remote code execution via a crafted
PDF — update immediately or restrict PDF downloads.

High risk to OpenSSL — allows a denial-of-service crash — patch to 3.0.8 or later.
```

CVSS score → severity word mapping:
| CVSS range | Severity word |
|------------|---------------|
| 9.0–10.0 | Critical |
| 7.0–8.9 | High |
| 4.0–6.9 | Medium |
| 0.1–3.9 | Low |
| None | Unknown severity |

KEV entries should add: `"— actively exploited in the wild"` to the sentence.

---

## Output format

### CSV columns (required for evaluation)

| Column | Source |
|--------|--------|
| `cve_id` | from match dict |
| `affected_asset` | `asset` from match dict |
| `cvss_score` | from match dict, empty if None |
| `epss_score` | from match dict, formatted to 4 d.p. |
| `kev_flag` | `"Yes"` / `"No"` from `in_kev` |
| `risk_description` | generated sentence |

### Console table (optional, for demo)

Use `tabulate` to print a readable table during the demo:

```python
from tabulate import tabulate
print(tabulate(rows, headers="keys", tablefmt="rounded_outline"))
```

---

## Suggested function structure

```python
def rank(matches: list[dict]) -> list[dict]:
    """Sort matches: KEV first, then EPSS descending."""

def make_risk_sentence(match: dict) -> str:
    """Generate a plain-English risk sentence for one CVE-asset row."""

def write_csv(ranked: list[dict], path: Path) -> None:
    """Write the ranked list to a CSV file."""

def main(matches: list[dict]) -> None:
    """Rank, generate sentences, print table, write CSV."""
```

---

## How to connect to Stage 3

```python
# ranker.py
from matcher import main as get_matches

matches = get_matches()   # runs the full matcher pipeline
ranked  = rank(matches)
write_csv(ranked, Path("output.csv"))
```

---

## Definition of done

- [ ] `rank()` — KEV first, then EPSS descending
- [ ] `make_risk_sentence()` — plain-English, no jargon
- [ ] `write_csv()` — all 6 required columns present
- [ ] Console table printed during demo
- [ ] `output.csv` generated and openable in Excel/Numbers
- [ ] Tested against full pipeline with real CVE data
