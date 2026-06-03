# CVE-to-My-Stack Translator
**CyberHack 2026 — CSE Connect Hackathon**

A tool that accepts a list of software assets and returns a short, prioritised, plain-English list of CVEs relevant to those assets, ranked by real-world exploitability.

## Dataset Status

| Feed | Location | Status |
|------|----------|--------|
| CISA KEV catalogue | `dataset/CISA-KEV/known_exploited_vulnerabilities.json` | ✅ Present |
| CPE dictionary (JSON 2.0) | `dataset/CPE-DICT/nvdcpe-2.0-chunk-00001.json` … `chunk-00016.json` | ✅ Present (16 × 50 MB chunks) |
| NVD CVE data | `dataset/NVD-CVE/` | ❌ Missing |
| EPSS scores | `dataset/` | ❌ Missing |
| Sample asset list | project root | ❌ Missing |
| Starter notebook | project root | ❌ Missing |

## Quick Start

See `.claude/project.md` for the full brief and build schedule.
