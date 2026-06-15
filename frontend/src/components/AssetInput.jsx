import { useRef } from "react";

export default function AssetInput({ value, onChange, onScan, loading }) {
  const fileRef = useRef(null);

  function handleFile(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => onChange(ev.target.result);
    reader.readAsText(file);
    // Reset so the same file can be re-uploaded
    e.target.value = "";
  }

  return (
    <div style={styles.wrapper}>
      <div style={styles.header}>
        <h2 style={styles.title}>Asset List</h2>
        <button style={styles.uploadBtn} onClick={() => fileRef.current.click()}>
          Upload .txt
        </button>
        {value && (
          <button style={styles.clearBtn} onClick={() => onChange("")}>
            Clear
          </button>
        )}
        <input
          ref={fileRef}
          type="file"
          accept=".txt,text/plain"
          style={{ display: "none" }}
          onChange={handleFile}
        />
      </div>
      <textarea
        style={styles.textarea}
        placeholder={"Enter one product per line, e.g.\nWindows Server 2022\nOpenSSL\nGoogle Chrome"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={10}
      />
      <button
        style={{ ...styles.scanBtn, opacity: loading ? 0.6 : 1 }}
        onClick={onScan}
        disabled={loading || !value.trim()}
      >
        {loading ? "Scanning…" : "Scan for CVEs"}
      </button>
    </div>
  );
}

const styles = {
  wrapper: { display: "flex", flexDirection: "column", gap: 10 },
  header: { display: "flex", alignItems: "center", gap: 12 },
  title: { margin: 0, fontSize: 18 },
  textarea: {
    width: "100%",
    fontFamily: "monospace",
    fontSize: 14,
    padding: "10px 12px",
    border: "1px solid #ccc",
    borderRadius: 6,
    resize: "vertical",
    boxSizing: "border-box",
  },
  uploadBtn: {
    padding: "6px 14px",
    fontSize: 13,
    cursor: "pointer",
    border: "1px solid #aac",
    borderRadius: 5,
    background: "#f0f4ff",
  },
  clearBtn: {
    padding: "6px 14px",
    fontSize: 13,
    cursor: "pointer",
    border: "1px solid #cca",
    borderRadius: 5,
    background: "#fff8f0",
    color: "#884400",
  },
  scanBtn: {
    alignSelf: "flex-start",
    padding: "10px 24px",
    fontSize: 15,
    fontWeight: 600,
    background: "#1a3a6e",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    cursor: "pointer",
  },
};
