# Claude Development Context

---

## On Session Start (Required — do this automatically, without being asked)

1. Read `.claude/project.md` for the full project brief, objectives, and constraints.
2. Check `dataset/` and `dataset scrape/` for any data files already present.
3. Note what is still missing from the expected file list (see **Data Feeds** below).

---

## Project Overview

**CVE-to-My-Stack Translator** — CyberHack 2026 (CSE Connect Hackathon).
A tool that accepts a list of software assets and returns a short, prioritised, plain-English list of CVEs relevant to those assets, ranked by real-world exploitability.

Target users are non-specialist, resource-constrained IT operators: solo SMB sysadmins, school IT teams, charity volunteers. Output must be actionable without security expertise.

---

## Files to Read Before Generating Code

| File | Why |
|------|-----|
| `.claude/project.md` | Full brief, goals, constraints, evaluation criteria |
| `dataset scrape/load_kev.py` | Existing KEV loader — follow its patterns for other loaders |

---

## Repository Structure

```
Hackathon-2026/
├── .claude/
│   ├── CLAUDE.md           # This file
│   └── project.md          # Full project brief (generated from PDF)
├── dataset/
│   ├── CISA-KEV/
│   │   └── known_exploited_vulnerabilities.json   # ✅ present
│   ├── CPE-DICT/
│   │   └── nvdcpe-2.0-chunk-00001.json … chunk-00016.json  # ✅ present (16 × 50 MB)
│   └── NVD-CVE/            # ❌ empty — CVE-2024.json / CVE-2025.json go here
├── dataset scrape/
│   └── load_kev.py         # CISA KEV downloader/parser (stdlib only)
├── CVE-to-My-Stack_Translator_Hackathon_Project_Guide_v01_new.pdf
└── README.md
```

---

## Data Files — Status

| File | Format | Location | Status |
|------|--------|----------|--------|
| `CVE-2024.json` | JSON | `dataset/NVD-CVE/` | ❌ missing |
| `CVE-2025.json` | JSON | `dataset/NVD-CVE/` | ❌ missing |
| `known_exploited_vulnerabilities.json` | JSON | `dataset/CISA-KEV/` | ✅ present |
| `epss_scores-[date].csv` | CSV | `dataset/` | ❌ missing |
| `nvdcpe-2.0-chunk-00001…00016.json` | JSON (16 chunks) | `dataset/CPE-DICT/` | ✅ present |
| `sample_asset_list.txt` | Plain text | project root | ❌ missing |
| `starter_notebook.ipynb` | Jupyter | project root | ❌ missing |

**CPE dictionary note:** The dictionary was downloaded as 16 × 50 MB JSON 2.0 chunks (NVD API format) rather than the single `official-cpe-dictionary_v2.3.xml` the guide describes. The data is equivalent. Loaders must iterate over all 16 chunk files. Key fields: `cpe.cpeName`, `cpe.titles[].title`.

No external API calls during the hackathon. All data must come from these local files.

---

## Tech Stack

**Primary: Python 3.10+**

| Library | Purpose |
|---------|---------|
| `pandas` | Load, filter, sort CVE and EPSS data |
| `rapidfuzz` | Fuzzy string matching for normalisation |
| `json` (stdlib) | Parse NVD CVE JSON and CISA KEV JSON |
| `gzip` / `lzma` (stdlib) | Decompress `.gz` EPSS and `.xz` NVD files |
| `tabulate` (optional) | Readable console output during dev |
| `Flask` (optional) | Minimal browser front end |

Jupyter notebook for exploration; `.py` script for final submission. No database — use pandas DataFrames or dicts in memory.

**Alternative: Vanilla JS** (Fuse.js, PapaParse — see `project.md` for details).

---

## Core Pipeline (in order)

1. **Normalise** — map user-supplied product names to CPE vendor/product strings using a hand-crafted dictionary + fuzzy matching. This is the hardest step.
2. **Match** — filter NVD CVE records whose CPE configuration blocks reference the matched identifiers.
3. **Enrich** — join matched CVEs with EPSS scores; flag any that appear in CISA KEV.
4. **Rank and output** — sort descending by EPSS; promote KEV entries to top; generate a plain-English risk sentence per CVE; write to CSV.

---

## Hard Constraints

- **No external API calls.** Do not call the NVD API, EPSS API, CISA API, or any live vulnerability data service.
- Work from the current year CVE file by default unless explicitly told otherwise.
- Normalisation dictionary must cover 15–20 product names accurately — not exhaustive coverage.
- Do not implement version range matching in the core build (it is a stretch goal).

---

## Output Format

The prioritised CVE table must include:

| Column | Description |
|--------|-------------|
| CVE ID | e.g. CVE-2024-12345 |
| Affected asset | Matched product from the user's asset list |
| CVSS score | Severity score (0–10) |
| EPSS score | Exploitation probability (0–1) |
| KEV flag | Yes/No — whether CISA confirmed active exploitation |
| Risk description | One plain-English sentence a non-expert can act on |

---

## Coding Conventions

- Follow the style in `dataset scrape/load_kev.py`: stdlib-first, clear function names, minimal dependencies.
- No external network calls at runtime.
- Keep everything in memory — no SQLite, no temporary files unless outputting the final CSV.
- Prefer `Path` from `pathlib` over string paths.
- Write functions that are independently testable (load, normalise, match, enrich, rank are separate steps).

---

## Known Limitations (be ready to explain these)

- Silent misses: when a product name fails to map to a CPE, the tool returns no results for that product without an error. Always log unmatched names.
- EPSS is predictive, not deterministic. Low EPSS does not mean safe.
- KEV covers confirmed exploitation only — absence from KEV does not mean unexploited.
- NVD enrichment is selective as of 2026 — older or lower-profile CVEs may have incomplete CPE data.

---

## Evaluation Criteria (equal weight)

1. Data pipeline — at least two of four feeds loaded and parsed correctly.
2. Normalisation quality — correct CPE matches; team can explain why it is the hardest part.
3. Matching accuracy — relevant results returned, false positives minimised.
4. Prioritisation logic — EPSS and KEV applied correctly; KEV entries surface first.
5. Output clarity — readable and actionable for a non-expert.
6. Explanation of limitations — team can articulate what the tool gets wrong and why.
