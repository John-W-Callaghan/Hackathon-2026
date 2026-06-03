import { useState } from "react";
import AssetInput from "./components/AssetInput.jsx";
import ResultsTable from "./components/ResultsTable.jsx";
import StatusBanner from "./components/StatusBanner.jsx";
import { postScan } from "./api.js";

export default function App() {
  const [assetText, setAssetText] = useState("");
  const [results, setResults] = useState(null);
  const [unmatched, setUnmatched] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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
        <AssetInput
          value={assetText}
          onChange={setAssetText}
          onScan={handleScan}
          loading={loading}
        />
        <StatusBanner loading={loading} error={error} />
        <ResultsTable results={results} unmatched={unmatched} />
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
};
