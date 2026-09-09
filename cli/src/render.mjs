/**
 * Terminal rendering: the in-place live view during a run, and the final report.
 *
 * Ports renderable() / _tool_table() / _print_report() from
 * backend/app/cli/main.py — same layout, same severity colours, same wording —
 * but with hand-rolled ANSI instead of Rich, so the package stays dependency-free.
 */

import {
  bold, dim, red, green, yellow, blue, magenta, cyan, gray,
  severityText, clip, visibleLength, hideCursor, showCursor, colorEnabled,
} from "./ansi.mjs";
import { TOOL_ORDER, TOOL_KIND, STAGE_LABELS } from "./monitor.mjs";

const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

const termWidth = () => process.stdout.columns || 90;
const reportWidth = () => Math.max(40, Math.min(termWidth(), 96));

const padEnd = (s, n) => String(s).padEnd(n);
const padStart = (s, n) => String(s).padStart(n);

// ── Live view ────────────────────────────────────────────────────────────────

function toolRow(name, row, frame) {
  let mark;
  switch (row.state) {
    case "running": mark = blue(SPINNER[frame % SPINNER.length]); break;
    case "ok": mark = green("✔"); break;
    case "failed": mark = yellow("!"); break;
    case "skipped": mark = dim("–"); break;
    default: mark = dim("·");
  }
  const count = row.state === "pending" || row.state === "running" ? "—" : String(row.count);
  const duration = row.duration ? `${row.duration.toFixed(1)}s` : "";
  let note = row.note || "";
  if (row.sample) note = note ? `sample data — ${note}` : "using sample data";

  return (
    `${mark} ${bold(padEnd(name, 11))} ${dim(padEnd(TOOL_KIND[name], 15))} ` +
    `${padStart(count, 4)} ${dim(padStart(duration, 6))}  ${dim(note)}`
  );
}

/** The multi-line live frame; mirrors ScanMonitor.renderable(). */
export function renderLive(monitor, frame) {
  const width = reportWidth();
  const lines = [];

  lines.push(bold("Static Analysis") + dim("  ·  5 scanners → merge → RAG triage → fixes"));
  lines.push(`${dim("target   ")}${cyan(monitor.target)}`);
  lines.push(`${dim("language ")}${monitor.language}`);
  lines.push(
    `${dim("stage    ")}${bold(blue(STAGE_LABELS[monitor.stage] || monitor.stage))}` +
    dim(`   (${Math.round(monitor.elapsedSeconds())}s elapsed)`)
  );
  lines.push("");

  for (const name of TOOL_ORDER) {
    lines.push(toolRow(name, monitor.tools[name], frame));
  }

  if (monitor.mergeStats && Object.keys(monitor.mergeStats).length) {
    const s = monitor.mergeStats;
    lines.push(
      `${dim("merge    ")}${s.total_raw || 0} raw ${dim("→")} ${bold(cyan(`${s.total_after_dedup || 0} unique`))}` +
      dim(`  (${s.duplicates_removed || 0} duplicates removed, ${s.multi_tool_confirmed || 0} multi-tool, ${s.with_taint_path || 0} with taint path)`)
    );
  }
  if (monitor.safePatterns) {
    lines.push(green(`controls ${monitor.safePatterns} existing security control(s) detected`));
  }
  if (monitor.ragMatched !== null) {
    lines.push(magenta(`rag      ${monitor.ragMatched}/${monitor.ragTotal} finding(s) matched a known-vulnerable pattern`));
  }
  if (monitor.triageTotal) {
    lines.push(
      `${dim("triage   ")}${blue(bar(monitor.triageDone, monitor.triageTotal))} ${monitor.triageDone}/${monitor.triageTotal}` +
      `${dim("   confirmed ")}${bold(red(String(monitor.confirmed)))}${dim("   ruled out ")}${bold(gray(String(monitor.discarded)))}`
    );
  }
  if (monitor.fixes) {
    lines.push(green(`fixes    ${monitor.fixes} remediation(s) generated`));
  }

  return lines.map((l) => clip(l, width)).join("\n");
}

function bar(done, total, width = 24) {
  if (total <= 0) return "░".repeat(width);
  const filled = Math.max(0, Math.min(width, Math.round((width * done) / total)));
  return "█".repeat(filled) + "░".repeat(width - filled);
}

/**
 * Redraws a block of text in place by moving the cursor up over the previous
 * frame and clearing to the end of the screen. No-op when stdout is not a TTY
 * (piped / CI) — the run then prints nothing until the final report.
 */
export class LiveView {
  constructor(stream = process.stdout) {
    this.stream = stream;
    this.lastLines = 0;
    this.active = colorEnabled && Boolean(stream.isTTY);
  }

  start() {
    if (this.active) hideCursor();
  }

  render(text) {
    if (!this.active) return;
    if (this.lastLines > 0) this.stream.write(`\x1b[${this.lastLines}A`); // cursor up
    this.stream.write("\x1b[0J"); // clear to end of screen
    this.stream.write(text + "\n");
    this.lastLines = text.split("\n").length;
  }

  stop() {
    if (this.active) showCursor();
    this.lastLines = 0;
  }
}

// ── Final report ───────────────────────────────────────────────────────────

/** A rounded-border panel with a title, wrapping the body to fit. */
function panel(title, body, width = reportWidth()) {
  const inner = width - 4;
  const bodyLines = [];
  for (const para of String(body).split("\n")) {
    const wrapped = wrapText(para, inner);
    for (const w of wrapped) bodyLines.push(w);
  }
  const top = `╭─ ${bold(title)} ${"─".repeat(Math.max(0, width - visibleLength(title) - 5))}╮`;
  const bottom = `╰${"─".repeat(width - 2)}╯`;
  const mid = bodyLines.map((l) => `│ ${l}${" ".repeat(Math.max(0, inner - visibleLength(l)))} │`);
  return [top, ...mid, bottom].join("\n");
}

function wrapText(text, width) {
  if (width <= 0) return [text];
  const words = text.split(/\s+/).filter(Boolean);
  if (words.length === 0) return [""];
  const lines = [];
  let line = "";
  for (const word of words) {
    if (!line) {
      line = word;
    } else if (visibleLength(line) + 1 + visibleLength(word) <= width) {
      line += ` ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);
  return lines;
}

const out = (s = "") => process.stdout.write(s + "\n");

/** Print the finished report: summary, per-tool accounting, then findings. */
export function printReport(report, { showFixes = false, maxFindings = 20 } = {}) {
  if (!report || Object.keys(report).length === 0) {
    out(yellow("No report was produced."));
    return;
  }

  out();
  const repo = report.source_repo || "";
  const scanned = repo || report.target_path || "";
  if (scanned) out(dim("scanned  ") + cyan(scanned) + (repo ? dim("  (cloned)") : ""));
  out(panel("Summary", report.summary || "No summary available."));

  // ── Headline counters ──
  out();
  const counter = (label, value) => out(`  ${dim(padEnd(label, 30))}${value}`);
  counter("unique findings", String(report.total_after_merge || 0));
  counter("confirmed", red(String(report.confirmed_count || 0)));
  counter("ruled out as false positives", String(report.ruled_out_count || 0));
  if (report.not_triaged_count) counter("not triaged (cap reached)", String(report.not_triaged_count));
  counter("fixes generated", green(String(report.fixes_count || 0)));
  counter("with a CodeQL taint path", String(report.with_taint_path_count || 0));

  // ── Severity breakdown of confirmed findings ──
  const severities = report.severity_breakdown || {};
  if (Object.keys(severities).length) {
    out();
    out(bold("Confirmed by severity"));
    for (const name of ["critical", "high", "medium", "low", "info"]) {
      if (severities[name]) out(`  ${padEnd(severityText(name), 18)} ${severities[name]}`);
    }
  }

  // ── Per-tool contribution ──
  const perTool = report.findings_per_tool || {};
  if (Object.keys(perTool).length) {
    out();
    out(bold("Per-tool contribution"));
    out(dim(`  ${padEnd("scanner", 13)}${padStart("raw", 5)}${padStart("after merge", 14)}${padStart("time", 8)}`));
    for (const name of TOOL_ORDER) {
      const e = perTool[name];
      if (!e) continue;
      const t = `${(e.duration_s || 0).toFixed(1)}s`;
      out(`  ${padEnd(name, 13)}${padStart(String(e.raw || 0), 5)}${padStart(String(e.after_merge || 0), 14)}${dim(padStart(t, 8))}`);
    }
  }

  // ── Confirmed findings ──
  const confirmed = report.confirmed_findings || [];
  if (confirmed.length) {
    out();
    out(bold("Confirmed findings"));
    for (const f of confirmed.slice(0, maxFindings)) {
      const evidence = f.taint_path
        ? "taint path"
        : f.multi_tool_confirmed
        ? "multi-tool"
        : "single tool";
      out(
        `  ${severityText(f.final_severity || f.severity)}  ${bold(f.category || "")}  ` +
        `${cyan(`${f.file}:${f.line}`)}  ${dim(`[${evidence}]`)}`
      );
      if (f.rule_id) out(`      ${dim(f.rule_id)}`);
      const reason = (f.triage_reason || "").trim();
      if (reason) out(`      ${reason}`);
      if (f.taint_path) {
        const chain = f.taint_path.map((step) => `${step.file}:${step.line}`).join(" → ");
        out(`      ${green("flow:")} ${dim(chain)}`);
      }
      out();
    }
    if (confirmed.length > maxFindings) {
      out(dim(`  …and ${confirmed.length - maxFindings} more (raise with --max-findings)`));
      out();
    }
  }

  // ── Existing security controls ──
  const safe = report.safe_patterns || [];
  if (safe.length) {
    out(bold(green("Security controls already in place")));
    for (const p of safe) {
      out(`  ${green("✔")} ${p.description || ""}`);
      out(`      ${dim(`${p.path}:${p.line}`)}`);
    }
    out();
  }

  // ── Fixes ──
  const fixes = report.fixes || [];
  if (fixes.length && showFixes) {
    out(bold("Generated fixes"));
    for (const fix of fixes) {
      out(`  ${cyan(`${fix.file}:${fix.line}`)} ${dim(`(${fix.rule_id}, grounded in ${fix.grounded_in})`)}`);
      out(panel("diff", fix.diff_text || ""));
      if (fix.explanation) out(`  ${fix.explanation}\n`);
    }
  } else if (fixes.length) {
    out(dim(`${fixes.length} fix(es) generated — rerun with --show-fixes to print the diffs.`));
  }

  // ── Warnings ──
  const errors = report.errors || [];
  if (errors.length) {
    out();
    out(yellow("Warnings"));
    for (const e of errors) out(`  ${yellow("•")} ${dim(e)}`);
  }
}
