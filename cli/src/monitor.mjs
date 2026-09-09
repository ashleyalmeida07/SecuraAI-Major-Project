/**
 * Port of ScanMonitor (backend/app/cli/main.py): fold each `node_update` event
 * into the running totals the terminal view needs.
 *
 * The graph streams one update per completed node, and the triage loop streams
 * one per finding, so state is accumulated here rather than re-derived from any
 * single partial snapshot — identical semantics to the Python monitor.
 */

// Mirrors frontend/src/lib/static-analysis.ts and main.py so the CLI and the
// web UI describe the same five engines in the same words.
export const TOOL_ORDER = ["semgrep", "bearer", "osv-scanner", "gitleaks", "codeql"];

export const TOOL_KIND = {
  semgrep: "SAST",
  bearer: "SAST + privacy",
  "osv-scanner": "SCA",
  gitleaks: "Secrets",
  codeql: "Taint analysis",
};

// Backend graph node name → the tool whose row it fills in.
const NODE_TO_TOOL = {
  run_semgrep: "semgrep",
  run_bearer: "bearer",
  run_osv_scanner: "osv-scanner",
  run_gitleaks: "gitleaks",
  run_codeql: "codeql",
};

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export const STAGE_LABELS = {
  dispatch: "Resolving target",
  scan: "Running 5 scanners in parallel",
  merge: "Merging and deduplicating",
  rag: "Retrieving similar known-vulnerable patterns",
  triage: "AI triage",
  fixes: "Generating fixes",
  report: "Building report",
  done: "Complete",
};

export class ScanMonitor {
  constructor(target, includeCodeql) {
    this.target = target;
    this.includeCodeql = includeCodeql;
    this.started = Date.now();
    this.stage = "dispatch";
    this.language = "detecting…";

    this.tools = {};
    for (const name of TOOL_ORDER) {
      this.tools[name] = { state: "pending", count: 0, duration: 0, note: "", sample: false };
    }
    if (!includeCodeql) {
      this.tools.codeql = {
        state: "skipped", count: 0, duration: 0, note: "skipped (--fast)", sample: false,
      };
    }

    this.mergeStats = {};
    this.safePatterns = 0;
    this.ragMatched = null;
    this.ragTotal = 0;

    this.triageDone = 0;
    this.triageTotal = 0;
    this.confirmed = 0;
    this.discarded = 0;

    this.fixes = 0;
    this.report = {};
    this.errors = [];
  }

  startScanners() {
    for (const row of Object.values(this.tools)) {
      if (row.state === "pending") row.state = "running";
    }
  }

  elapsedSeconds() {
    return (Date.now() - this.started) / 1000;
  }

  /** Fold one `node_update` into the running totals. */
  ingest(node, state) {
    const s = state || {};

    if (node === "dispatch") {
      this.language = s.codeql_language || "auto";
      this.stage = "scan";
      this.startScanners();
      return;
    }

    if (node in NODE_TO_TOOL) {
      const tool = NODE_TO_TOOL[node];
      const status = (s.tool_status || {})[tool] || {};
      const skipped = String(status.note || "").toLowerCase().includes("skipped");
      this.tools[tool] = {
        state: skipped ? "skipped" : status.ok ? "ok" : "failed",
        count: status.finding_count || 0,
        duration: status.duration_s || 0,
        note: status.note || "",
        sample: Boolean(status.used_sample),
      };
      return;
    }

    if (node === "merge_findings") {
      this.stage = "merge";
      this.mergeStats = s.merge_stats || {};
      this.safePatterns = (s.safe_patterns || []).length;
      return;
    }

    if (node === "retrieve_context") {
      this.stage = "rag";
      const findings = s.merged_findings || [];
      this.ragTotal = findings.length;
      this.ragMatched = findings.filter((f) => (f.context || []).length).length;
      return;
    }

    if (node === "triage") {
      this.stage = "triage";
      const progress = s.triage_progress || {};
      if (progress.done !== undefined && progress.done !== null) this.triageDone = progress.done;
      if (progress.total !== undefined && progress.total !== null) this.triageTotal = progress.total;
      return;
    }

    if (node === "confirm_finding") {
      this.confirmed += (s.triaged_findings || []).length || 1;
      return;
    }

    if (node === "discard_finding") {
      this.discarded += (s.false_positives || []).length || 1;
      return;
    }

    if (node === "fix_generator") {
      this.stage = "fixes";
      this.fixes = (s.fixes || []).length;
      this.errors.push(...(s.errors || []));
      return;
    }

    if (node === "report_builder") {
      this.stage = "report";
      this.report = s.static_report || {};
    }
  }
}
