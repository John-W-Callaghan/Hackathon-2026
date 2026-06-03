# Stage 3 — CVE Matching (Hour 3)

## Status: Complete (blocked on NVD data files)

---

## What this stage does

Scans all NVD CVE records and finds every CVE whose CPE applicability block references
one of the CPE fragments returned by Stage 2. Returns an enriched list of CVE-asset hits
ready for ranking in Stage 4.

---

## File: `matcher.py`

### Pipeline position

```
normalisation.py → matcher.py → ranker.py (Stage 4)
```

`matcher.py` imports `normalise()` from `normalisation.py` and is designed to be imported
by `ranker.py`. Calling `main()` returns the matches list so the ranker can use it
directly.

---

## Functions

### `load_cve_records(path)`

Reads `CVE-2024.json` and returns the flat list under the `"cve_items"` key.

**Known issue — path is wrong:**
```python
CVE_FILE = Path("data/CVE-2024.json")   # ← incorrect
```
Should be:
```python
CVE_FILE = Path(__file__).parent / "dataset" / "NVD-CVE" / "CVE-2024.json"
```
Fix this when the NVD files arrive.

### `extract_cpe_strings(record)`

Walks `configurations → nodes → cpeMatch → criteria` and returns all CPE strings for a
record. Records with no CPE data are skipped — they cannot be matched.

### `extract_cvss(record)`

Returns the highest-version CVSS base score available, with a fallback chain:
v3.1 → v3.0 → v2 → `None`

### `extract_description(record)`

Returns the English description string from `descriptions[]`, or `""` if absent.

### `build_asset_cpe_map(assets)`

Calls `normalise()` for each asset and collects results into:
```python
{ "Adobe Acrobat Reader DC": ["adobe:acrobat_reader_dc", "adobe:acrobat_reader", ...], ... }
```
Assets that return `[]` from `normalise()` are excluded and logged — they will produce
no CVE results, but this is explicit, not silent.

### `match_cves(records, asset_cpe_map, kev_set, epss_dict)`

Core matching function. For each CVE record, checks whether any CPE fragment for any
asset appears as a substring of any CPE criteria string in that record.

```python
hit = any(
    fragment in cpe
    for fragment in fragments
    for cpe in cpe_strings
)
```

Substring containment is intentional — CPE criteria strings include the full
`cpe:2.3:a:vendor:product:version:...` form, so matching `"openssl:openssl"` against
that string works without parsing the full CPE.

Returns a list of dicts with shape:

```python
{
    "cve_id":      str,    # e.g. "CVE-2024-12345"
    "asset":       str,    # matched asset name from the user's list
    "description": str,    # English description from NVD
    "cvss_score":  float | None,
    "epss_score":  float,  # 0.0 if epss_dict not supplied
    "in_kev":      bool,   # False if kev_set not supplied
}
```

`kev_set` and `epss_dict` are optional — the matcher works standalone without them.
When the loaders are ready, pass them in:

```python
from dataset_scrape.load_kev import load_vulnerabilities, build_lookup_structures
vulns = load_vulnerabilities(KEV_PATH)
kev_set, _ = build_lookup_structures(vulns)

from epss_loader import epss_raw as epss_dict

matches = match_cves(records, asset_cpe_map, kev_set=kev_set, epss_dict=epss_dict)
```

### `print_match_summary(matches)`

Diagnostic only — prints match count per asset, sorted descending. Remove or suppress
before the final demo if output is too noisy.

---

## Current blockers

1. **NVD CVE files missing** — `CVE-2024.json` and `CVE-2025.json` have not arrived yet.
   The matcher cannot run until at least one is present.

2. **Wrong CVE file path** — `CVE_FILE = Path("data/CVE-2024.json")` needs to be updated
   to `Path(__file__).parent / "dataset" / "NVD-CVE" / "CVE-2024.json"`.

3. **KEV and EPSS not wired into `main()`** — the comment block in `main()` shows exactly
   what to add. This is a two-line import change once the NVD data arrives.

---

## Definition of done

- [x] `load_cve_records()` implemented
- [x] `extract_cpe_strings()` implemented
- [x] `extract_cvss()` implemented with v3.1/v3.0/v2 fallback
- [x] `extract_description()` implemented
- [x] `build_asset_cpe_map()` implemented with unmatched-asset logging
- [x] `match_cves()` implemented with optional KEV/EPSS parameters
- [x] Return shape correct for Stage 4 ranker
- [ ] Fix `CVE_FILE` path
- [ ] Wire KEV and EPSS into `main()` once NVD data arrives
- [ ] End-to-end run against real CVE data
