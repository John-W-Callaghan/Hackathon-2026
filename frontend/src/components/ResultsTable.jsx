import { useState } from "react";

const KEV_TOOLTIP = {
  title: "Known Exploited Vulnerabilities (KEV)",
  body: "A US government list of flaws actively used in real attacks. \"YES\" means act now.",
};

const EPSS_TOOLTIP = {
  title: "Exploit Prediction Scoring System (EPSS)",
  body: "Likelihood (0–1) this flaw gets exploited within 30 days. Higher = more urgent.",
};

const CVSS_TOOLTIP = {
  title: "Common Vulnerability Scoring System (CVSS)",
  body: "Severity score from 0–10. 9–10 is Critical, 7–8.9 is High, 4–6.9 is Medium, below 4 is Low. Measures potential impact, not how likely it is to be exploited.",
};

const COLUMNS = [
  { key: "cve_id",           label: "CVE ID",           sortable: false },
  { key: "description",      label: "Description",      sortable: false },
  { key: "asset",            label: "Asset",            sortable: false },
  { key: "cvss_score",       label: "Risk Score",       sortable: true,  tooltip: CVSS_TOOLTIP },
  { key: "epss_score",       label: "EPSS",             sortable: true,  tooltip: EPSS_TOOLTIP },
  { key: "in_kev",           label: "KEV",              sortable: true, tooltip: KEV_TOOLTIP },
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
  const [tooltipOpen, setTooltipOpen] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  function handleTooltipEnter(e, col) {
    const rect = e.currentTarget.getBoundingClientRect();
    setTooltipPos({ x: rect.left + rect.width / 2, y: rect.bottom + 8 });
    setTooltipOpen(col.key);
  }

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

      {tooltipOpen && (() => {
        const col = COLUMNS.find((c) => c.key === tooltipOpen);
        return col?.tooltip ? (
          <div
            role="tooltip"
            style={{
              ...styles.tooltip,
              position: "fixed",
              left: tooltipPos.x,
              top: tooltipPos.y,
              transform: "translateX(-50%)",
            }}
          >
            <strong style={styles.tooltipTitle}>{col.tooltip.title}</strong>
            <p style={styles.tooltipBody}>{col.tooltip.body}</p>
          </div>
        ) : null;
      })()}

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
                    position: "relative",
                  }}
                  onClick={col.sortable ? () => handleSort(col.key) : undefined}
                >
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                    {col.label}
                    {col.tooltip && (
                      <span
                        style={styles.infoIcon}
                        onMouseEnter={(e) => handleTooltipEnter(e, col)}
                        onMouseLeave={() => setTooltipOpen(null)}
                        onClick={(e) => e.stopPropagation()}
                        aria-label={`What is ${col.label}?`}
                      >
                        ⓘ
                      </span>
                    )}
                  </span>
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
  infoIcon: {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    width: 16,
    height: 16,
    fontSize: 13,
    cursor: "default",
    opacity: 0.85,
    position: "relative",
    userSelect: "none",
  },
  tooltip: {
    width: 220,
    background: "#1a1a2e",
    color: "#f0f0f0",
    borderRadius: 8,
    padding: "12px 14px",
    boxShadow: "0 4px 20px rgba(0,0,0,0.35)",
    zIndex: 999,
    pointerEvents: "none",
    textAlign: "left",
    lineHeight: 1.5,
    fontWeight: 400,
  },
  tooltipTitle: {
    display: "block",
    fontSize: 13,
    fontWeight: 700,
    color: "#f8c94a",
    marginBottom: 6,
    letterSpacing: 0.2,
  },
  tooltipBody: {
    margin: 0,
    fontSize: 12,
    color: "#ddd",
    lineHeight: 1.6,
  },
};
