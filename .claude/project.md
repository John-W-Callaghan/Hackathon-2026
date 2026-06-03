# Project 1: The CVE-to-My-Stack Translator

**Event:** CyberHack 2026 (CSE Connect Hackathon)
**Duration:** 5.30 hours maximum
**Skill level:** Intermediate (some Python experience required)
**Team size:** 3 to 5 participants
**Context:** Cyber security education and SMB vulnerability management

---

## What the Project Is

Every working day, dozens of new CVEs (Common Vulnerabilities and Exposures) are published. Small IT teams cannot read them all, let alone determine which ones apply to their specific software environment. The result is information overload that leads to either security paralysis or blanket patching — both of which waste time.

The CVE-to-My-Stack Translator solves this by accepting a list of software assets as input and returning a short, prioritised, plain-English list of CVEs that are actually relevant to those assets, ranked by real-world exploitability.

**Core problem in one sentence:** A small IT administrator cannot filter hundreds of daily CVEs to the three or four that actually affect their systems. This tool does that for them.

---

## Target Users

The tool is designed for non-specialist or resource-constrained IT operators:

- **Solo SMB sysadmin** — pastes an asset list, gets back a handful of relevant CVEs with urgency signals, and knows immediately which one to patch first.
- **School or university IT support team** — runs the tool weekly and exports a CSV for the CISO's weekly report.
- **Charity or third-sector IT volunteer** — runs the tool quarterly to check whether certified software has become vulnerable, using plain-English output that requires no security expertise to interpret.

---

## Key Goals and Objectives

**Primary aim:** Build a working tool that takes a list of software assets and returns a prioritised, plain-English list of relevant CVEs ranked by real-world exploitability.

**Core objectives (must be complete by end of session):**

1. Load and parse at least one offline data feed (NVD CVE data, CISA KEV, or EPSS scores).
2. Build a normalisation function that maps at least 15 to 20 common software names to their CPE identifiers.
3. Implement a matching function that filters the CVE dataset to entries relevant to the user's asset list.
4. Apply EPSS scores and KEV flags to rank filtered CVEs by urgency.
5. Produce a structured output (CSV or printed table) including CVE ID, affected asset, EPSS score, KEV flag, and a plain-English risk summary.
6. Demonstrate the tool working against the facilitator-provided sample asset list.

**Stretch goals (if time allows):**

- Generate a one-page summary brief in addition to the CSV output.
- Add a combined urgency score using both CVSS severity and EPSS probability.
- Handle version range matching (e.g. a CVE affecting versions 3.0 to 3.5 matched against an asset running version 3.2).
- Add a command-line interface that accepts an asset list file as an argument.

---

## Technical Approach

### Core Concepts

| Term | Definition |
|------|------------|
| CVE | Common Vulnerability and Exposure — a unique identifier for a publicly known security flaw. |
| NVD | National Vulnerability Database — the US government repository maintained by NIST. |
| CPE | Common Platform Enumeration — a structured naming scheme for software and hardware used to precisely match CVE records to products. |
| CVSS | Common Vulnerability Scoring System — a numerical severity score (0 to 10; 9+ is Critical). |
| EPSS | Exploit Prediction Scoring System — a probability score (0 to 1) estimating likelihood of exploitation in the next 30 days. |
| KEV | Known Exploited Vulnerabilities — a CISA catalogue of CVEs confirmed as actively exploited in the wild. KEV membership is the strongest urgency signal. |
| Normalisation | Mapping informal product names (e.g. "Office 365") to their canonical CPE identifiers — the hardest and most important step in the build. |

### Data Pipeline

The pipeline has four stages:

1. **Normalisation** — map user-supplied product names to CPE vendor/product strings using a hand-crafted dictionary and fuzzy matching.
2. **CVE matching** — filter the NVD dataset to CVEs whose CPE configuration blocks reference the matched CPE identifiers.
3. **Enrichment** — join matched CVEs with EPSS scores and flag any that appear in the CISA KEV catalogue.
4. **Ranking and output** — sort by EPSS score descending, promote KEV entries to the top, generate a plain-English risk sentence per CVE, and write to CSV.

### Technology Options

Two equally valid approaches are supported:

**Approach A: Python (back-end / data pipeline)**

| Library | Purpose |
|---------|---------|
| pandas | Loading, filtering, and sorting CVE and EPSS data |
| rapidfuzz | Fuzzy string matching for normalisation |
| json (stdlib) | Parsing NVD CVE JSON and CISA KEV JSON |
| gzip / lzma (stdlib) | Decompressing .gz EPSS and .xz NVD files |
| tabulate (optional) | Readable console table output during development |
| Flask (optional) | Minimal browser-based front end |

Requirements: Python 3.10 or later. A Jupyter notebook is recommended for exploration; a plain .py script is acceptable for final submission. No database is required — keep everything in memory using pandas DataFrames or Python dictionaries.

**Approach B: Web technologies (front-end / full-stack)**

| Technology | Role |
|------------|------|
| HTML / CSS / JavaScript | Core stack (vanilla JS is sufficient) |
| Fuse.js | Fuzzy matching for normalisation |
| PapaParse | CSV parsing for EPSS data |
| React (optional) | UI framework |
| Node.js + Express (optional) | Local server for back-end JavaScript pipeline |

Practical notes: use the browser File API for asset list upload; render output as an HTML table with a downloadable CSV option via Blob URL; load only what is needed from the large NVD JSON files.

Teams with mixed skills may split the work — Python for the data pipeline and a simple HTML front end that reads the Python-generated CSV output.

---

## Data Feeds

All data is pre-downloaded and provided at the start of the session. No external API calls are permitted during the hackathon.

| Feed | Source | Format | Purpose |
|------|--------|--------|---------|
| NVD CVE data | github.com/fkie-cad/nvd-json-data-feeds | JSON (.xz) | Primary CVE database with CVSS scores and CPE applicability |
| CISA KEV catalogue | cisa.gov/known-exploited-vulnerabilities | JSON | Flags confirmed actively exploited CVEs |
| EPSS scores | epss.empiricalsecurity.com | CSV (.gz) | Daily exploitation probability scores per CVE |
| CPE dictionary | nvd.nist.gov/vuln/data-feeds | JSON 2.0 (16 chunks) | Reference for official product identifiers |

**Note:** NVD legacy 1.1 JSON feeds were retired in August 2025. The hackathon uses the Fraunhofer FKIE community reconstruction, which mirrors the NVD data in the same per-year JSON format.

### Files Provided on the Day

| File | Format | Description |
|------|--------|-------------|
| CVE-2024.json | JSON | NVD CVE data for 2024 — **❌ missing** |
| CVE-2025.json | JSON | NVD CVE data for 2025 — **❌ missing** |
| known_exploited_vulnerabilities.json | JSON | CISA KEV catalogue — **✅ present** at `dataset/CISA-KEV/` |
| epss_scores-[date].csv | CSV | EPSS scores for all CVEs — **❌ missing** |
| nvdcpe-2.0-chunk-00001…00016.json | JSON 2.0 | CPE dictionary (16 × 50 MB chunks) — **✅ present** at `dataset/CPE-DICT/` |
| sample_asset_list.txt | Plain text | Sample asset list for testing — **❌ missing** |
| starter_notebook.ipynb | Jupyter | Starter notebook with file loading code — **❌ missing** |

---

## Deliverables

| Output | Description |
|--------|-------------|
| Prioritised CVE table | Ranked list with columns: CVE ID, affected asset, CVSS score, EPSS score, KEV flag, plain-English risk description |
| Normalisation dictionary | Python dictionary or CSV mapping common product names to CPE identifiers, covering at least 15 to 20 widely used SMB software titles |
| Working script | A Python script (or web app) that accepts an asset list and produces the prioritised CVE table, running cleanly against the sample asset list |
| Demo output | A 5-minute maximum presentation showing the tool running against the sample asset list and explaining the design decisions made |

---

## Suggested Build Schedule

| Hour | Focus |
|------|-------|
| Hour 1 (0:00–1:00) | Data loading and exploration — load EPSS CSV, CISA KEV JSON, NVD CVE JSON, and the sample asset list |
| Hour 2 (1:00–2:00) | Normalisation dictionary — build and test the CPE mapping for at least 15 common product names |
| Hour 3 (2:00–3:00) | CVE matching and filtering — filter NVD dataset by CPE, merge with EPSS scores and KEV flags |
| Hour 4 (3:00–4:00) | Ranking and output — sort by EPSS/KEV, generate plain-English risk sentences, write CSV |
| Hour 5 (4:00–5:00) | Testing, refinement, and demo preparation — run full pipeline, fix edge cases, prepare 5-minute demo |

---

## Sample Asset List (for Testing)

The normalisation dictionary must handle at least 10 of these entries:

| Product Name | Version | Category |
|--------------|---------|----------|
| Microsoft 365 Apps for Business | Current | Productivity |
| Windows Server 2022 | 21H2 | Server OS |
| Windows 10 Pro | 22H2 | Desktop OS |
| Adobe Acrobat Reader DC | 2024.001 | PDF reader |
| Cisco IOS XE | 17.9 | Router firmware |
| VMware vSphere | 8.0 | Virtualisation |
| Google Chrome | Latest | Browser |
| OpenSSL | 3.0.7 | Cryptography library |
| Apache HTTP Server | 2.4.57 | Web server |
| Zoom | 5.17 | Video conferencing |
| WordPress | 6.4 | CMS |
| Moodle | 4.3 | LMS |

---

## Constraints

**Hard constraints:**
- No external APIs. All data must be used from the pre-downloaded files. Do not call the NVD API, FIRST API, CISA API, or any other online vulnerability data service.
- 5-hour time limit. The tool must be demo-ready within the session window.
- Internet access is permitted for documentation, AI tools, and search engines — but not for live vulnerability data APIs.

**Scope constraints:**
- Work with the current year CVE file only unless told otherwise.
- The normalisation dictionary needs to cover 15 to 20 product names accurately, not every product ever made.
- Do not attempt version range matching in the core build — exact version matching is sufficient for the MVP. Version ranges are a stretch goal.

**Known limitations to be aware of and able to explain:**
- CVE matching fails silently when product names do not align with CPE identifiers. A missed mapping produces a missed result, not an error message. This is the core challenge of the project.
- EPSS scores are predictive, not deterministic. A low EPSS score does not mean a CVE is safe.
- The CISA KEV catalogue covers confirmed exploitation only. A CVE not in KEV may simply not have been confirmed or reported, not necessarily unexploited.
- As of 2026, NVD enrichment is selective — NIST prioritises CVEs in the KEV catalogue and those affecting federal government software. Older or lower-profile CVEs may have incomplete CPE data.

---

## Evaluation Criteria

Each criterion carries equal weight:

| Criterion | What is assessed |
|-----------|-----------------|
| Data pipeline | Can at least two of the four data feeds be loaded and correctly parsed? |
| Normalisation quality | Does the dictionary produce correct CPE matches? Can the team explain why normalisation is the hardest part? |
| Matching accuracy | Does the CVE filter return genuinely relevant results and avoid false positives? |
| Prioritisation logic | Are EPSS scores and KEV flags applied correctly? Are KEV entries surfaced at the top? |
| Output clarity | Is the output readable and useful to a non-expert? Could the Use Case 1 sysadmin act on it without further explanation? |
| Explanation of limitations | Can the team clearly articulate what the tool gets wrong and why? |
