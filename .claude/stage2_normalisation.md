# Stage 2 — Normalisation (Hour 2)

## Status: Complete

See also: `normalise.md` for the original detailed reference with demo talking points.

---

## What this stage does

Maps informal user-supplied product names (e.g. "Microsoft 365 Apps for Business") to
canonical CPE vendor:product strings (e.g. `microsoft:365_apps`) that appear in NVD CVE
records.

This is the hardest and most important step in the pipeline. A wrong mapping does not
raise an error — it silently returns zero CVEs for that product. There is no warning
beyond the one printed by `normalise()`.

---

## File: `normalisation.py`

### Dataset path constants

Centralised here so other modules can import them instead of repeating path logic:

```python
DATA_DIR      = Path(__file__).parent / "dataset"
CPE_DICT_PATH = DATA_DIR / "official-cpe-dictionary_v2.3.xml"   # expected, not present
KEV_PATH      = DATA_DIR / "CISA-KEV" / "known_exploited_vulnerabilities.json"
NVD_2024_PATH = DATA_DIR / "NVD-CVE"  / "CVE-2024.json"
NVD_2025_PATH = DATA_DIR / "NVD-CVE"  / "CVE-2025.json"
EPSS_DIR      = DATA_DIR / "EPSS"
EPSS_GLOB     = "epss_scores-*.csv.gz"
```

### CPE_MAP — hardcoded dictionary

15 product entries, verified against the CVE-2024.json CPE strings:

| Informal name | CPE vendor:product strings |
|---------------|---------------------------|
| Microsoft 365 Apps for Business | `microsoft:365_apps` |
| Windows 10 Pro | `microsoft:windows_10_22h2`, `microsoft:windows_10_21h2` |
| Windows Server 2022 | `microsoft:windows_server_2022`, `microsoft:windows_server_2022_23h2` |
| Windows Server 2019 | `microsoft:windows_server_2019` |
| Adobe Acrobat Reader DC | `adobe:acrobat_reader_dc`, `adobe:acrobat_reader`, `adobe:acrobat_dc` |
| Cisco IOS XE | `cisco:ios_xe` |
| VMware vSphere | `vmware:vcenter_server`, `vmware:workstation` |
| Google Chrome | `google:chrome` |
| OpenSSL | `openssl:openssl` |
| Apache HTTP Server | `apache:http_server` |
| Zoom | `zoom:zoom`, `zoom:rooms_controller` |
| WordPress | `wordpress:wordpress` |
| Moodle | `moodle:moodle` |

**Multi-CPE cases to note for the demo:**
- Adobe Acrobat — fragmented across three CPE product names across CVE years
- VMware vSphere — a suite, not one product; maps to `vcenter_server` and `workstation`
- Windows 10 — newer records use version-specific CPEs (`22h2`, `21h2`)
- Zoom — product name varies by year across the NVD

### `normalise(asset_name)` function

1. Exact match against `CPE_MAP` keys — fastest path, no fuzzy overhead
2. Fuzzy match via `rapidfuzz.process.extractOne` with `fuzz.WRatio`, cutoff 70%
3. Returns `[]` and prints a WARNING if no match exceeds the cutoff

```python
def normalise(asset_name: str) -> list[str]:
```

The 70% cutoff is intentional — below it, the risk of a false positive (matching the
wrong product) outweighs the risk of a miss.

### CPE dictionary loader (for when `official-cpe-dictionary_v2.3.xml` arrives)

`load_cpe_dictionary(path)` — streams the XML with `ET.iterparse` to avoid loading the
full file into memory, builds a `{ title: [vendor:product, ...] }` index.

`build_extended_map(path)` — merges the XML index into `CPE_MAP`, with `CPE_MAP` entries
taking priority (they are verified; the XML titles may be verbose or ambiguous).

If the XML file is not present, `load_cpe_dictionary()` returns `{}` and the pipeline
falls back to the hardcoded map without error.

**Note:** The CPE data that arrived is 16 JSON chunks in `dataset/CPE-DICT/`, not the
XML. The XML loader is a stub for the originally expected format. The JSON chunks are
usable for manual lookups but are not yet wired into `normalise()`.

---

## Definition of done

- [x] `CPE_MAP` has 15+ entries
- [x] All 12 sample assets resolve without WARNING
- [x] Multi-CPE cases handled (Adobe, VMware, Windows 10)
- [x] Fuzzy fallback working with 70% cutoff
- [x] Dataset path constants centralised
- [ ] CPE dictionary JSON chunks wired in as extended lookup (stretch)
