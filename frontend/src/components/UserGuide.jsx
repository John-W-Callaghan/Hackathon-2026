import { useState } from "react";

export default function UserGuide() {
  const [open, setOpen] = useState(true);

  return (
    <div style={styles.card}>
      <button style={styles.toggle} onClick={() => setOpen((o) => !o)}>
        <span style={styles.toggleLabel}>How it works</span>
        <span style={styles.chevron}>{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div style={styles.body}>
          <div style={styles.steps}>
            <Step
              number="1"
              heading="List your software"
              text='Type the name of each app, operating system, or service your organisation uses — one per line. For example: "Windows Server 2022", "Apache 2.4", "OpenSSL". You can also upload a plain .txt file.'
            />
            <Step
              number="2"
              heading="Click Scan for CVEs"
              text="The tool matches your software against a database of known security vulnerabilities (CVEs) and fetches their latest risk scores — all offline, no data leaves your machine."
            />
            <Step
              number="3"
              heading="Review the ranked results"
              text="Results appear sorted worst-first. The most urgent items sit at the top. Each row includes a plain-English description of the risk and what to do about it."
            />
          </div>

          <div style={styles.glossary}>
            <span style={styles.glossaryHeading}>Reading the scores —</span>
            <GlossaryItem
              term="CVSS"
              def="Severity of the vulnerability on a scale of 0–10. Above 7 is High or Critical."
            />
            <GlossaryItem
              term="EPSS"
              def="Probability (%) that this vulnerability will be exploited within the next 30 days. Higher = act sooner."
            />
            <GlossaryItem
              term="KEV"
              def='Yes means CISA has confirmed attackers are actively exploiting this vulnerability right now. Treat these as your highest priority regardless of score.'
            />
          </div>
        </div>
      )}
    </div>
  );
}

function Step({ number, heading, text }) {
  return (
    <div style={stepStyles.row}>
      <div style={stepStyles.badge}>{number}</div>
      <div>
        <div style={stepStyles.heading}>{heading}</div>
        <div style={stepStyles.text}>{text}</div>
      </div>
    </div>
  );
}

function GlossaryItem({ term, def }) {
  return (
    <span style={glossaryStyles.item}>
      <strong style={glossaryStyles.term}>{term}:</strong> {def}
    </span>
  );
}

const styles = {
  card: {
    background: "#eef3fb",
    border: "1px solid #b8cef0",
    borderRadius: 8,
    marginBottom: 24,
    overflow: "hidden",
  },
  toggle: {
    width: "100%",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    background: "none",
    border: "none",
    padding: "12px 16px",
    cursor: "pointer",
    textAlign: "left",
  },
  toggleLabel: {
    fontWeight: 700,
    fontSize: 15,
    color: "#1a3a6e",
  },
  chevron: {
    fontSize: 11,
    color: "#1a3a6e",
    opacity: 0.7,
  },
  body: {
    padding: "0 16px 16px",
    display: "flex",
    flexDirection: "column",
    gap: 14,
  },
  steps: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
  },
  glossary: {
    background: "#fff",
    border: "1px solid #d0ddf5",
    borderRadius: 6,
    padding: "10px 14px",
    fontSize: 13,
    color: "#333",
    lineHeight: 1.6,
    display: "flex",
    flexDirection: "column",
    gap: 3,
  },
  glossaryHeading: {
    fontWeight: 700,
    fontSize: 13,
    color: "#1a3a6e",
    marginBottom: 2,
  },
};

const stepStyles = {
  row: {
    display: "flex",
    alignItems: "flex-start",
    gap: 12,
  },
  badge: {
    minWidth: 26,
    height: 26,
    borderRadius: "50%",
    background: "#1a3a6e",
    color: "#fff",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: 700,
    fontSize: 13,
    marginTop: 1,
  },
  heading: {
    fontWeight: 700,
    fontSize: 14,
    color: "#1a3a6e",
    marginBottom: 2,
  },
  text: {
    fontSize: 13,
    color: "#444",
    lineHeight: 1.55,
  },
};

const glossaryStyles = {
  item: {
    display: "block",
  },
  term: {
    color: "#1a3a6e",
  },
};
