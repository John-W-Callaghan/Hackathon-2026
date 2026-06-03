import { Router } from "express";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import path from "path";

const router = Router();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PIPELINE_SCRIPT = path.resolve(__dirname, "../python/run_pipeline.py");
// Project root is two levels up from backend/routes/
const PROJECT_ROOT = path.resolve(__dirname, "../../");

router.post("/scan", (req, res) => {
  const { assets } = req.body;

  if (!Array.isArray(assets) || assets.length === 0) {
    return res.status(400).json({ error: "assets must be a non-empty array" });
  }

  const py = spawn("python3", [PIPELINE_SCRIPT], { cwd: PROJECT_ROOT });

  let stdout = "";
  let stderr = "";

  py.stdout.on("data", (chunk) => { stdout += chunk; });
  py.stderr.on("data", (chunk) => { stderr += chunk; });

  py.on("close", (code) => {
    if (code !== 0) {
      console.error("Pipeline stderr:\n", stderr);
      return res.status(500).json({ error: "Pipeline failed", detail: stderr.slice(0, 500) });
    }

    try {
      const result = JSON.parse(stdout);
      return res.json(result);
    } catch {
      console.error("Failed to parse pipeline output:", stdout.slice(0, 200));
      return res.status(500).json({ error: "Invalid pipeline output" });
    }
  });

  py.on("error", (err) => {
    return res.status(500).json({ error: "Failed to spawn Python", detail: err.message });
  });

  // Write asset list to stdin, one per line
  py.stdin.write(assets.join("\n"));
  py.stdin.end();
});

export default router;
