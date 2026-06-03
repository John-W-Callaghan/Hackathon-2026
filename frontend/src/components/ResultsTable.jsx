import { useState } from "react";

const COLUMNS = [
  { key: "cve_id",           label: "CVE ID",           sortable: false },
  { key: "description",      label: "Description",      sortable: false },
  { key: "asset",            label: "Asset",            sortable: false },
  { key: "cvss_score",       label: "CVSS",             sortable: true  },
  { key: "epss_score",       label: "EPSS",             sortable: true  },
  { key: "in_kev",           label: "KEV",              sortable: true  },
  { key: "risk_description", label: "Risk Description", sortable: false },
];

const TRUNCATE_LEN = 80;
function truncate(text) {
  if (!text) return "—";
  return text.length <= TRUNCATE_LEN ? text : text.slice(0, TRUNCATE_LEN).trimEnd() + "…";
}

function sortRows(rows, key, dir) {
  return [...rows].sort((a, b) => {
    const av = a[key] ?? (key === "in_kev" ? false : -Infinity);
    const bv = b[key] ?? (key === "in_kev" ? false : -Infinity);
    if (av === bv) return 0;
    // booleans: true > false
    const gt = typeof av === "boolean" ? (av ? 1 : -1) : av > bv ? 1 : -1;
    return dir === "desc" ? -gt : gt;
  });
}

export default function ResultsTable({ results, unmatched, yearFilter = "all" }) {
  const [sortKey, setSortKey] = useState("in_kev");
  const [sortDir, setSortDir] = useState("desc");

  if (!results) return null;

  function handleSort(key) {
    if (sortKey === key) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  }

  const sorted = sortRows(results, sortKey, sortDir);

  return (
    <div style={styles.wrapper}>
      {unmatched.length > 0 && (
        <div style={styles.unmatched}>
          <strong>Unmatched assets</strong> (no CVE data found): {unmatched.join(", ")}
        </div>
      )}

      {results.length === 0 && yearFilter !== "all" ? (
        <div style={styles.noResults}>
          No {yearFilter} CVEs found for the scanned assets. Try switching to "All years".
        </div>
      ) : (
        <p style={styles.count}>
          {results.length} CVE{results.length !== 1 ? "s" : ""} found
          {yearFilter !== "all" ? ` (${yearFilter} only)` : ""}. Click a column header to sort.
        </p>
      )}

      <div style={styles.tableWrapper}>
        <table style={styles.table}>
          <thead>
            <tr>
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  style={{
                    ...styles.th,
                    ...(col.sortable ? styles.thSortable : {}),
                    ...(sortKey === col.key ? styles.thActive : {}),
                  }}
                  onClick={col.sortable ? () => handleSort(col.key) : undefined}
                >
                  {col.label}
                  {col.sortable && (
                    <span style={styles.arrow}>
                      {sortKey === col.key ? (sortDir === "desc" ? " ▼" : " ▲") : " ⇅"}
                    </span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((r, i) => (
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
                <td style={{ ...styles.td, ...styles.nameCell }} title={r.description || undefined}>
                  {truncate(r.description)}
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
    userSelect: "none",
  },
  thSortable: {
    cursor: "pointer",
  },
  thActive: {
    background: "#122d57",
  },
  arrow: {
    fontSize: 11,
    opacity: 0.8,
  },
  td: {
    padding: "8px 12px",
    borderBottom: "1px solid #e0e0e0",
    verticalAlign: "top",
  },
  nameCell: {
    maxWidth: 260,
    fontSize: 13,
    color: "#333",
    cursor: "default",
  },
  noResults: {
    padding: "12px 16px",
    background: "#fffbe6",
    border: "1px solid #e6c800",
    borderRadius: 6,
    fontSize: 14,
    color: "#665500",
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
