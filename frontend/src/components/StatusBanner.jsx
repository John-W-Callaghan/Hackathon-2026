export default function StatusBanner({ loading, error }) {
  if (loading) {
    return (
      <div style={styles.banner}>
        <span style={styles.spinner} /> Scanning — this may take 30–60 seconds while the pipeline runs…
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ ...styles.banner, background: "#fff0f0", borderColor: "#f66" }}>
        Error: {error}
      </div>
    );
  }

  return null;
}

const styles = {
  banner: {
    padding: "12px 16px",
    margin: "12px 0",
    background: "#f0f4ff",
    border: "1px solid #99b",
    borderRadius: 6,
    display: "flex",
    alignItems: "center",
    gap: 10,
    fontSize: 14,
  },
  spinner: {
    display: "inline-block",
    width: 16,
    height: 16,
    border: "3px solid #aac",
    borderTopColor: "#336",
    borderRadius: "50%",
    animation: "spin 0.8s linear infinite",
  },
};
