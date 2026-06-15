import { useState } from "react";
import AssetInput from "./components/AssetInput.jsx";
import ResultsTable from "./components/ResultsTable.jsx";
import StatusBanner from "./components/StatusBanner.jsx";
import UserGuide from "./components/UserGuide.jsx";
import { postScan } from "./api.js";

export default function App() {
  const [assetText, setAssetText] = useState("");
  const [results, setResults] = useState(null);
  const [unmatched, setUnmatched] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [yearFilter, setYearFilter] = useState("all");

  async function handleScan() {
    const assets = assetText
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

    if (assets.length === 0) return;

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const data = await postScan(assets);
      setResults(data.results);
      setUnmatched(data.unmatched || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <h1 style={styles.title}>CVE-to-My-Stack Translator</h1>
        <p style={styles.subtitle}>
          Paste or upload your software asset list to see which CVEs affect your stack, ranked by real-world exploitability.
        </p>
      </header>

      <main style={styles.main}>
        <UserGuide />
        <AssetInput
          value={assetText}
          onChange={setAssetText}
          onScan={handleScan}
          loading={loading}
        />
        <StatusBanner loading={loading} error={error} />
        {results && (
          <div style={styles.filterRow}>
            <label style={styles.filterLabel} htmlFor="year-filter">CVE Year</label>
            <select
              id="year-filter"
              style={styles.filterSelect}
              value={yearFilter}
              onChange={(e) => setYearFilter(e.target.value)}
            >
              <option value="all">All years</option>
              <option value="2026">2026 only</option>
              <option value="2025">2025 only</option>
              <option value="2024">2024 only</option>
            </select>
          </div>
        )}
        <ResultsTable
          results={results === null ? null : (
            yearFilter === "all"
              ? results
              : results.filter((r) => r.cve_id.startsWith(`CVE-${yearFilter}-`))
          )}
          unmatched={unmatched}
          yearFilter={yearFilter}
        />
      </main>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: system-ui, sans-serif; background: #f5f7fa; }
      `}</style>
    </div>
  );
}

const styles = {
  page: { minHeight: "100vh" },
  header: {
    background: "#1a3a6e",
    color: "#fff",
    padding: "28px 40px 24px",
  },
  title: { margin: "0 0 8px", fontSize: 26, fontWeight: 700 },
  subtitle: { margin: 0, fontSize: 15, opacity: 0.85 },
  main: {
    maxWidth: 1100,
    margin: "0 auto",
    padding: "28px 40px",
  },
  filterRow: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    margin: "16px 0 4px",
  },
  filterLabel: {
    fontSize: 14,
    fontWeight: 600,
    color: "#333",
  },
  filterSelect: {
    padding: "6px 12px",
    fontSize: 14,
    border: "1px solid #aac",
    borderRadius: 5,
    background: "#f0f4ff",
    cursor: "pointer",
  },
};
