export default function ResultsTable({ results, unmatched }) {
  if (!results) return null;

  return (
    <div style={styles.wrapper}>
      {unmatched.length > 0 && (
        <div style={styles.unmatched}>
          <strong>Unmatched assets</strong> (no CVE data found): {unmatched.join(", ")}
        </div>
      )}

      <p style={styles.count}>
        {results.length} CVE{results.length !== 1 ? "s" : ""} found — KEV entries shown first, then ranked by EPSS.
      </p>

      <div style={styles.tableWrapper}>
        <table style={styles.table}>
          <thead>
            <tr>
              {["CVE ID", "Asset", "CVSS", "EPSS", "KEV", "Risk Description"].map((h) => (
                <th key={h} style={styles.th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results.map((r, i) => (
              <tr key={r.cve_id + i} style={r.in_kev ? styles.kevRow : undefined}>
                <td style={styles.td}>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${r.cve_id}`}
                    target="_blank"
                    rel="noreferrer"
                    style={styles.link}
                  >
                    {r.cve_id}
                  </a>
                </td>
                <td style={styles.td}>{r.asset}</td>
                <td style={{ ...styles.td, ...cvssColor(r.cvss_score) }}>
                  {r.cvss_score ?? "N/A"}
                </td>
                <td style={styles.td}>{r.epss_score?.toFixed(3) ?? "—"}</td>
                <td style={styles.td}>
                  {r.in_kev
                    ? <span style={styles.kevBadge}>YES</span>
                    : <span style={styles.noBadge}>No</span>}
                </td>
                <td style={{ ...styles.td, maxWidth: 420, fontSize: 13 }}>{r.risk_description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function cvssColor(score) {
  if (score == null) return {};
  if (score >= 9) return { color: "#b00020", fontWeight: 700 };
  if (score >= 7) return { color: "#c45000", fontWeight: 600 };
  if (score >= 4) return { color: "#7a6000" };
  return { color: "#357a35" };
}

const styles = {
  wrapper: { marginTop: 24 },
  count: { margin: "0 0 12px", color: "#555", fontSize: 14 },
  unmatched: {
    padding: "10px 14px",
    background: "#fffbe6",
    border: "1px solid #e6c800",
    borderRadius: 6,
    marginBottom: 12,
    fontSize: 13,
  },
  tableWrapper: { overflowX: "auto" },
  table: {
    width: "100%",
    borderCollapse: "collapse",
    fontSize: 14,
  },
  th: {
    textAlign: "left",
    padding: "8px 12px",
    background: "#1a3a6e",
    color: "#fff",
    whiteSpace: "nowrap",
  },
  td: {
    padding: "8px 12px",
    borderBottom: "1px solid #e0e0e0",
    verticalAlign: "top",
  },
  kevRow: { background: "#fff5f5" },
  kevBadge: {
    background: "#b00020",
    color: "#fff",
    padding: "2px 8px",
    borderRadius: 4,
    fontSize: 12,
    fontWeight: 700,
  },
  noBadge: {
    background: "#e8e8e8",
    color: "#555",
    padding: "2px 8px",
    borderRadius: 4,
    fontSize: 12,
  },
  link: { color: "#1a3a6e", fontWeight: 600 },
};
