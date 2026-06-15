# CVE-to-My-Stack Translator
**CyberHack 2026 — CSE Connect Hackathon**

A tool for small IT teams that answers one question: **"Which security vulnerabilities actually affect my software?"**

Every day, hundreds of new CVEs (security flaws) are published. Most of them won't affect you — but finding the ones that do takes time and expertise most small teams don't have. This tool takes your list of software, cross-references it against national vulnerability databases, and hands back a short, prioritised list of the ones you actually need to worry about — ranked by how likely they are to be exploited.

---

## What it does

1. You provide a list of software your organisation runs (e.g. Windows 10, Chrome, OpenSSL).
2. The tool matches each product against the NVD (National Vulnerability Database).
3. Each matched CVE is enriched with:
   - **EPSS score** — the probability it will be exploited in the next 30 days (0–1)
   - **KEV flag** — whether CISA has confirmed it is actively being exploited right now
4. Results are ranked with the most dangerous CVEs at the top and saved as a CSV report.

---

## Quick start

### Requirements

- Python 3.10 or later
- Install dependencies:

```bash
pip install -r requirements.txt
```

### Data files

Dataset files are not stored in the repository (they are too large). On the first run, the backend automatically downloads them from public sources:

| Dataset | Source | Size |
|---------|--------|------|
| CISA KEV | cisa.gov | ~1 MB |
| NVD CVE 2024–2026 | github.com/fkie-cad/nvd-json-data-feeds | ~300 MB |
| EPSS scores | epss.cyentia.com | ~30 MB |

**The first startup will take a few minutes** while files download. Subsequent runs are instant — existing files are never re-downloaded.

To download manually before starting the server:

```bash
python download_datasets.py
```

### Run the full pipeline

```bash
python ranker.py
```

This runs all four stages automatically and writes a `cve_report.csv` to the project root.

### Run the tests

```bash
python -m unittest test_pipeline -v
```

All 51 tests should pass. No data files are needed to run the tests.

---

## Web app

A browser front end is available, backed by a Flask API.

### Backend (Flask)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python3 backend/app.py
```

This loads the CVE/EPSS/KEV data once at startup and serves:

- `GET /api/health` — health check
- `POST /api/scan` — body `{"assets": ["Windows 10", "Google Chrome", ...]}`, returns `{"results": [...], "unmatched": [...]}`

The server listens on `http://localhost:3001`.

### Frontend (Vite + React)

```bash
cd frontend
npm install
npm run dev
```

The dev server runs on `http://localhost:5173` and proxies `/api` requests to the Flask backend on port 3001.

---

## How it works

The pipeline has four stages, each in its own file:

| Stage | File | What it does |
|-------|------|--------------|
| 1. Normalise | `normalisation.py` | Maps product names like "Google Chrome" to their official CPE identifiers |
| 2. Match | `matcher.py` | Scans CVE records for any that mention your products |
| 3. Enrich | `matcher.py` | Adds EPSS scores and KEV flags to each match |
| 4. Rank & output | `ranker.py` | Sorts by urgency, writes a plain-English risk sentence, saves CSV |

The data acquisition scripts (for downloading/refreshing the source files) live in `dataset scrape/`.

---

## Output

The tool produces a `cve_report.csv` and a console summary table. Each row contains:

| Column | Example | What it means |
|--------|---------|---------------|
| CVE ID | CVE-2024-1234 | The unique identifier for the vulnerability |
| Affected asset | OpenSSL | Which of your products is affected |
| CVSS score | 9.8 | Severity out of 10 (9+ is Critical) |
| EPSS score | 0.9412 | Probability of exploitation in the next 30 days |
| KEV flag | Yes | Whether CISA has confirmed active exploitation in the wild |
| Risk description | Plain English summary | One sentence a non-expert can act on |

KEV entries always appear at the top — patch those first.

---

## Supported products

The tool recognises these products out of the box. Fuzzy matching also handles minor variations (e.g. "Chrome Browser" will match "Google Chrome").

| Product | Product |
|---------|---------|
| Microsoft 365 Apps for Business | Adobe Acrobat Reader DC |
| Windows 10 Pro | Cisco IOS XE |
| Windows Server 2022 | VMware vSphere |
| Google Chrome | Zoom |
| OpenSSL | WordPress |
| Apache HTTP Server | Moodle |

To add more products, edit the `CPE_MAP` dictionary in `normalisation.py`.

---

## Known limitations

- **Silent misses** — if a product name can't be matched to a CPE identifier, it returns no results rather than an error. Unmatched names are always printed as warnings.
- **EPSS is a prediction, not a guarantee** — a low score doesn't mean a CVE is safe, only that exploitation is statistically less likely in the near term.
- **KEV covers confirmed exploitation only** — a CVE absent from KEV may simply not have been reported yet.
- **NVD data quality** — some CVEs, particularly older or lower-profile ones, have incomplete CPE data and may not be matched even if relevant.

---

## Project structure

```
Hackathon-2026/
├── dataset/                  # Data files (gitignored — too large to commit)
│   ├── CISA-KEV/
│   ├── CPE-DICT/
│   ├── EPSS/
│   └── NVD-CVE/
├── dataset scrape/           # Scripts for downloading/refreshing data files
│   ├── load_kev.py
│   └── load_cve.py
├── backend/                  # Flask API serving the pipeline to the web app
│   └── app.py
├── frontend/                 # Vite + React web app
├── normalisation.py          # Stage 1: product name → CPE identifier
├── matcher.py                # Stage 2–3: CVE matching and enrichment
├── ranker.py                 # Stage 4: ranking, risk sentences, CSV output
├── epss_loader.py            # EPSS score loader (imported by matcher)
├── test_pipeline.py          # Unit tests
├── requirements.txt          # Python dependencies (rapidfuzz, flask, etc.)
└── cve_report.csv            # Generated output (created when you run ranker.py)
```
