'''test_pipeline.py — Unit tests for the CVE-to-My-Stack pipeline.

Run:  python -m unittest test_pipeline -v

Covers all four stages:
  1. normalisation.py  — CPE mapping and fuzzy matching
  2. matcher.py        — record extraction and CVE matching
  3. epss_loader.py    — file parsing and score normalisation
  4. ranker.py         — sorting, risk sentences, CSV output
'''

import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

class _FakeGzFile:
    """Mimics the text-mode context manager returned by gzip.open(..., 'rt')."""
    def __init__(self, text):
        self._io = io.StringIO(text)

    def __enter__(self):
        return self._io

    def __exit__(self, *a):
        pass


_FAKE_EPSS_TEXT = (
    "# model_version=v2024,score_date=2026-05-19\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.5000,0.9500\n"
    "CVE-2024-0002,0.0050,0.2000\n"
    "CVE-2024-0003,0.0010,0.1000\n"
)

# Patch gzip.open before epss_loader is imported so the module-level
# load_epss() call reads synthetic data rather than the real file.
with patch("gzip.open", return_value=_FakeGzFile(_FAKE_EPSS_TEXT)):
    if "epss_loader" in sys.modules:
        del sys.modules["epss_loader"]
    import epss_loader
    from epss_loader import load_epss, normalise_minmax, build_combined

from normalisation import normalise, CPE_MAP
from matcher import (
    extract_cpe_strings,
    extract_cvss,
    extract_description,
    build_asset_cpe_map,
    match_cves,
)
from ranker import build_risk_sentence, rank, write_csv


def _make_record(
    cve_id: str,
    cpe_criteria: list | None = None,
    cvss31: float | None = None,
    cvss30: float | None = None,
    cvss2: float | None = None,
    description: str = "A test vulnerability.",
) -> dict:
    """Build a minimal NVD-format CVE record for use in tests."""
    record: dict = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": description}],
        "configurations": [],
        "metrics": {},
    }
    if cpe_criteria:
        record["configurations"] = [
            {"nodes": [{"cpeMatch": [{"criteria": c} for c in cpe_criteria]}]}
        ]
    if cvss31 is not None:
        record["metrics"]["cvssMetricV31"] = [{"cvssData": {"baseScore": cvss31}}]
    if cvss30 is not None:
        record["metrics"]["cvssMetricV30"] = [{"cvssData": {"baseScore": cvss30}}]
    if cvss2 is not None:
        record["metrics"]["cvssMetricV2"] = [{"cvssData": {"baseScore": cvss2}}]
    return record


def _make_match(
    cve_id: str = "CVE-2024-0001",
    asset: str = "OpenSSL",
    cvss: float = 7.5,
    epss: float = 0.05,
    in_kev: bool = False,
    description: str = "A test vulnerability.",
) -> dict:
    return {
        "cve_id": cve_id,
        "asset": asset,
        "cvss_score": cvss,
        "epss_score": epss,
        "in_kev": in_kev,
        "description": description,
    }


# ---------------------------------------------------------------------------
# Stage 1 — Normalisation
# ---------------------------------------------------------------------------

class TestNormalisation(unittest.TestCase):

    def test_exact_match_openssl(self):
        self.assertIn("openssl:openssl", normalise("OpenSSL"))

    def test_exact_match_windows_10(self):
        result = normalise("Windows 10 Pro")
        self.assertTrue(any("windows_10" in f for f in result))

    def test_exact_match_chrome(self):
        self.assertEqual(normalise("Google Chrome"), ["google:chrome"])

    def test_exact_match_cisco(self):
        self.assertIn("cisco:ios_xe", normalise("Cisco IOS XE"))

    def test_fuzzy_match_close_name(self):
        # "Chrome Browser" is not in CPE_MAP; should fuzzy-match to "Chrome"
        result = normalise("Chrome Browser")
        self.assertIn("google:chrome", result)

    def test_unknown_product_returns_empty(self):
        self.assertEqual(normalise("NonExistentProduct XYZ 9000"), [])

    def test_all_cpe_map_keys_resolve(self):
        """Every hardcoded CPE_MAP key must return at least one fragment."""
        for key in CPE_MAP:
            with self.subTest(key=key):
                self.assertTrue(normalise(key), f"'{key}' returned empty — check CPE_MAP")


# ---------------------------------------------------------------------------
# Stage 2 — Matcher: extraction helpers
# ---------------------------------------------------------------------------

class TestExtractCpeStrings(unittest.TestCase):

    def test_returns_all_criteria(self):
        record = _make_record("CVE-2024-1000", cpe_criteria=[
            "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*",
            "cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*",
        ])
        result = extract_cpe_strings(record)
        self.assertEqual(len(result), 2)
        self.assertIn("cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*", result)

    def test_empty_when_no_configurations(self):
        self.assertEqual(extract_cpe_strings(_make_record("CVE-2024-1001")), [])


class TestExtractCvss(unittest.TestCase):

    def test_prefers_v31_over_v30_and_v2(self):
        record = _make_record("CVE-2024-2000", cvss31=9.8, cvss30=8.0, cvss2=7.5)
        self.assertEqual(extract_cvss(record), 9.8)

    def test_falls_back_to_v30(self):
        record = _make_record("CVE-2024-2001", cvss30=8.0, cvss2=7.5)
        self.assertEqual(extract_cvss(record), 8.0)

    def test_falls_back_to_v2(self):
        record = _make_record("CVE-2024-2002", cvss2=6.5)
        self.assertEqual(extract_cvss(record), 6.5)

    def test_returns_none_when_absent(self):
        self.assertIsNone(extract_cvss(_make_record("CVE-2024-2003")))


class TestExtractDescription(unittest.TestCase):

    def test_returns_english_description(self):
        record = _make_record("CVE-2024-3000", description="Remote code execution flaw.")
        self.assertEqual(extract_description(record), "Remote code execution flaw.")

    def test_returns_empty_string_when_no_descriptions(self):
        record = {"id": "CVE-2024-3001", "descriptions": [], "configurations": [], "metrics": {}}
        self.assertEqual(extract_description(record), "")


# ---------------------------------------------------------------------------
# Stage 2 — Matcher: CVE matching
# ---------------------------------------------------------------------------

class TestMatchCves(unittest.TestCase):

    def _sample_records(self):
        return [
            _make_record("CVE-2024-4001", cpe_criteria=[
                "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"
            ], cvss31=9.8, description="OpenSSL buffer overflow."),
            _make_record("CVE-2024-4002", cpe_criteria=[
                "cpe:2.3:a:google:chrome:120.0:*:*:*:*:*:*:*"
            ], cvss31=7.5, description="Chrome sandbox escape."),
            _make_record("CVE-2024-4003"),  # no CPE data — must never match
        ]

    def test_matches_single_asset(self):
        matches = match_cves(self._sample_records(), {"OpenSSL": ["openssl:openssl"]})
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["cve_id"], "CVE-2024-4001")
        self.assertEqual(matches[0]["asset"], "OpenSSL")

    def test_matches_multiple_assets(self):
        asset_map = {
            "OpenSSL": ["openssl:openssl"],
            "Google Chrome": ["google:chrome"],
        }
        matches = match_cves(self._sample_records(), asset_map)
        cve_ids = {m["cve_id"] for m in matches}
        self.assertIn("CVE-2024-4001", cve_ids)
        self.assertIn("CVE-2024-4002", cve_ids)

    def test_no_match_for_unrelated_asset(self):
        matches = match_cves(self._sample_records(), {"WordPress": ["wordpress:wordpress"]})
        self.assertEqual(matches, [])

    def test_record_without_cpe_is_skipped(self):
        matches = match_cves(self._sample_records(), {"OpenSSL": ["openssl:openssl"]})
        self.assertNotIn("CVE-2024-4003", [m["cve_id"] for m in matches])

    def test_kev_flag_is_applied(self):
        matches = match_cves(
            self._sample_records(),
            {"OpenSSL": ["openssl:openssl"]},
            kev_set={"CVE-2024-4001"},
        )
        self.assertTrue(matches[0]["in_kev"])

    def test_kev_false_when_not_in_set(self):
        matches = match_cves(
            self._sample_records(),
            {"OpenSSL": ["openssl:openssl"]},
            kev_set={"CVE-2024-9999"},
        )
        self.assertFalse(matches[0]["in_kev"])

    def test_epss_score_is_applied(self):
        matches = match_cves(
            self._sample_records(),
            {"OpenSSL": ["openssl:openssl"]},
            epss_dict={"CVE-2024-4001": 0.42},
        )
        self.assertAlmostEqual(matches[0]["epss_score"], 0.42)

    def test_epss_defaults_to_zero_when_absent(self):
        matches = match_cves(self._sample_records(), {"OpenSSL": ["openssl:openssl"]})
        self.assertEqual(matches[0]["epss_score"], 0.0)


class TestBuildAssetCpeMap(unittest.TestCase):

    def test_known_assets_are_included(self):
        result = build_asset_cpe_map(["OpenSSL", "Google Chrome"])
        self.assertIn("OpenSSL", result)
        self.assertIn("Google Chrome", result)

    def test_unknown_asset_is_excluded(self):
        result = build_asset_cpe_map(["SuperFakeProduct 9000"])
        self.assertNotIn("SuperFakeProduct 9000", result)

    def test_empty_input_returns_empty_map(self):
        self.assertEqual(build_asset_cpe_map([]), {})


# ---------------------------------------------------------------------------
# Stage 3 — EPSS loader
# ---------------------------------------------------------------------------

class TestEpssLoader(unittest.TestCase):

    def test_module_loaded_expected_cves(self):
        self.assertIn("CVE-2024-0001", epss_loader.epss_raw)
        self.assertIn("CVE-2024-0002", epss_loader.epss_raw)

    def test_raw_scores_are_correct(self):
        self.assertAlmostEqual(epss_loader.epss_raw["CVE-2024-0001"], 0.5000)
        self.assertAlmostEqual(epss_loader.epss_raw["CVE-2024-0002"], 0.0050)

    def test_percentile_scores_are_correct(self):
        self.assertAlmostEqual(epss_loader.epss_percentile["CVE-2024-0001"], 0.95)

    def test_load_epss_parses_fake_file(self):
        fake_text = (
            "# model_version=v2024,score_date=2026-05-19\n"
            "cve,epss,percentile\n"
            "CVE-2024-9999,0.7500,0.9900\n"
        )
        with patch("gzip.open", return_value=_FakeGzFile(fake_text)):
            raw, pct = load_epss(Path("dummy.csv.gz"))
        self.assertAlmostEqual(raw["CVE-2024-9999"], 0.75)
        self.assertAlmostEqual(pct["CVE-2024-9999"], 0.99)

    def test_load_epss_rejects_missing_comment_line(self):
        bad_text = "cve,epss,percentile\nCVE-2024-0001,0.5,0.9\n"
        with patch("gzip.open", return_value=_FakeGzFile(bad_text)):
            with self.assertRaises(ValueError):
                load_epss(Path("dummy.csv.gz"))

    def test_normalise_minmax_scales_to_zero_and_one(self):
        result = normalise_minmax({"A": 0.0, "B": 0.5, "C": 1.0})
        self.assertAlmostEqual(result["A"], 0.0)
        self.assertAlmostEqual(result["C"], 1.0)
        self.assertAlmostEqual(result["B"], 0.5)

    def test_normalise_minmax_all_same_returns_zeros(self):
        result = normalise_minmax({"A": 0.3, "B": 0.3, "C": 0.3})
        self.assertTrue(all(v == 0.0 for v in result.values()))

    def test_build_combined_contains_all_keys(self):
        result = build_combined({"X": 0.1}, {"X": 0.8}, {"X": 0.5})
        self.assertIn("X", result)
        self.assertSetEqual(set(result["X"].keys()), {"epss", "percentile", "epss_normalised"})
        self.assertAlmostEqual(result["X"]["epss"], 0.1)


# ---------------------------------------------------------------------------
# Stage 4 — Ranker
# ---------------------------------------------------------------------------

class TestRiskSentence(unittest.TestCase):

    def test_contains_cve_id_and_asset(self):
        m = _make_match(cve_id="CVE-2024-0001", asset="OpenSSL")
        s = build_risk_sentence(m)
        self.assertIn("CVE-2024-0001", s)
        self.assertIn("OpenSSL", s)

    def test_kev_entry_mentions_active_exploitation(self):
        s = build_risk_sentence(_make_match(epss=0.25, in_kev=True))
        self.assertIn("actively exploited", s.lower())

    def test_non_kev_entry_does_not_mention_active_exploitation(self):
        s = build_risk_sentence(_make_match(epss=0.001, in_kev=False))
        self.assertNotIn("actively exploited", s.lower())

    def test_epss_label_low(self):
        self.assertIn("low", build_risk_sentence(_make_match(epss=0.005)))

    def test_epss_label_moderate(self):
        self.assertIn("moderate", build_risk_sentence(_make_match(epss=0.05)))

    def test_epss_label_high(self):
        self.assertIn("high", build_risk_sentence(_make_match(epss=0.15)))

    def test_epss_boundary_low_to_moderate(self):
        self.assertIn("moderate", build_risk_sentence(_make_match(epss=0.01)))

    def test_epss_boundary_moderate_to_high(self):
        self.assertIn("high", build_risk_sentence(_make_match(epss=0.10)))


class TestRank(unittest.TestCase):

    def test_kev_entries_come_first(self):
        matches = [
            _make_match("CVE-2024-0001", epss=0.80, in_kev=False),
            _make_match("CVE-2024-0002", epss=0.01, in_kev=True),
        ]
        ranked = rank(matches)
        self.assertEqual(ranked[0]["cve_id"], "CVE-2024-0002")

    def test_non_kev_sorted_by_epss_descending(self):
        matches = [
            _make_match("CVE-2024-0001", epss=0.10),
            _make_match("CVE-2024-0002", epss=0.50),
            _make_match("CVE-2024-0003", epss=0.25),
        ]
        ranked = rank(matches)
        scores = [m["epss_score"] for m in ranked]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_kev_group_also_sorted_by_epss_descending(self):
        matches = [
            _make_match("CVE-2024-0001", epss=0.10, in_kev=True),
            _make_match("CVE-2024-0002", epss=0.90, in_kev=True),
        ]
        ranked = rank(matches)
        self.assertEqual(ranked[0]["cve_id"], "CVE-2024-0002")

    def test_risk_description_attached_to_every_row(self):
        matches = [_make_match(), _make_match("CVE-2024-0002")]
        ranked = rank(matches)
        for m in ranked:
            with self.subTest(cve=m["cve_id"]):
                self.assertIn("risk_description", m)
                self.assertGreater(len(m["risk_description"]), 0)

    def test_empty_input_returns_empty(self):
        self.assertEqual(rank([]), [])


class TestWriteCsv(unittest.TestCase):

    def _write_and_read(self, matches):
        ranked = rank(matches)
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            write_csv(ranked, path=tmp_path)
            with tmp_path.open(newline="", encoding="utf-8") as fh:
                return list(csv.DictReader(fh))
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_row_count_matches_input(self):
        matches = [_make_match("CVE-2024-0001"), _make_match("CVE-2024-0002")]
        rows = self._write_and_read(matches)
        self.assertEqual(len(rows), 2)

    def test_required_columns_present(self):
        rows = self._write_and_read([_make_match()])
        for col in ("cve_id", "asset", "cvss_score", "epss_score", "in_kev", "risk_description"):
            with self.subTest(col=col):
                self.assertIn(col, rows[0])

    def test_kev_entry_is_first_row(self):
        matches = [
            _make_match("CVE-2024-0001", epss=0.90, in_kev=False),
            _make_match("CVE-2024-0002", epss=0.01, in_kev=True),
        ]
        rows = self._write_and_read(matches)
        self.assertEqual(rows[0]["cve_id"], "CVE-2024-0002")

    def test_risk_description_written_to_csv(self):
        rows = self._write_and_read([_make_match(in_kev=True, epss=0.5)])
        self.assertIn("actively exploited", rows[0]["risk_description"].lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
