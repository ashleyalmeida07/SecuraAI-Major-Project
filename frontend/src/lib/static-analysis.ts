/**
 * Shared presentation metadata for the Static Analysis flow.
 *
 * The scan page, reports page, and dashboard all need to label the same five
 * scanners and the same severity bands, so the mapping lives in one place.
 */

import type { ToolSource, MergedFinding, TaintStep } from "@/lib/api";

export interface ToolMeta {
  /** Backend `tool_source` value. */
  id: ToolSource;
  label: string;
  /** What kind of analysis it performs — shown as a chip. */
  kind: string;
  /** One line on what it is good at. */
  blurb: string;
  color: string;
}

export const TOOL_META: Record<ToolSource, ToolMeta> = {
  semgrep: {
    id: "semgrep",
    label: "Semgrep",
    kind: "SAST",
    blurb: "Pattern-based rules across every language in the repo",
    color: "#00d4ff",
  },
  bearer: {
    id: "bearer",
    label: "Bearer",
    kind: "SAST + Privacy",
    blurb: "Dataflow-aware rules with strong CWE/OWASP tagging",
    color: "#a78bfa",
  },
  "osv-scanner": {
    id: "osv-scanner",
    label: "OSV-Scanner",
    kind: "SCA",
    blurb: "Lockfile dependencies matched against the OSV advisory database",
    color: "#f59e0b",
  },
  gitleaks: {
    id: "gitleaks",
    label: "Gitleaks",
    kind: "Secrets",
    blurb: "Hardcoded credentials and API keys (values redacted)",
    color: "#ec4899",
  },
  codeql: {
    id: "codeql",
    label: "CodeQL",
    kind: "Taint Analysis",
    blurb: "Full source → sink dataflow paths — proof of reachability",
    color: "#10b981",
  },
};

export const TOOL_ORDER: ToolSource[] = [
  "semgrep",
  "bearer",
  "osv-scanner",
  "gitleaks",
  "codeql",
];

export function toolMeta(id: string): ToolMeta {
  return (
    TOOL_META[id as ToolSource] ?? {
      id: id as ToolSource,
      label: id,
      kind: "Scanner",
      blurb: "",
      color: "#64748b",
    }
  );
}

/** Tailwind classes per severity, for badges and borders. */
export const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-violet-500/10 text-violet-400 border-violet-500/30",
};

export function severityStyle(severity?: string): string {
  return SEVERITY_STYLES[(severity || "").toLowerCase()] ?? SEVERITY_STYLES.info;
}

export const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** The severity a finding should be displayed at (post-triage wins). */
export function displaySeverity(finding: Partial<MergedFinding>): string {
  return (finding.final_severity || finding.severity || "info").toLowerCase();
}

/**
 * Rank a finding by evidence strength. A CodeQL taint path is the strongest
 * signal available — it shows tainted data actually reaches a dangerous sink —
 * followed by independent agreement between tools.
 */
export type EvidenceTier = "taint_path" | "multi_tool" | "single_tool";

export function evidenceTier(finding: Partial<MergedFinding>): EvidenceTier {
  if (finding.taint_path && finding.taint_path.length > 0) return "taint_path";
  if (finding.multi_tool_confirmed) return "multi_tool";
  return "single_tool";
}

export const EVIDENCE_LABEL: Record<EvidenceTier, string> = {
  taint_path: "Taint path — reachable",
  multi_tool: "Corroborated by multiple tools",
  single_tool: "Single-tool pattern match",
};

export const EVIDENCE_STYLE: Record<EvidenceTier, string> = {
  taint_path: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  multi_tool: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  single_tool: "bg-secondary text-muted-foreground border-border",
};

/** "routes.js:12 → db.js:40" — a compact one-line rendering of a taint path. */
export function taintChain(path: TaintStep[]): string {
  return path.map((step) => `${step.file}:${step.line}`).join(" → ");
}

export const ROLE_STYLE: Record<string, string> = {
  source: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  intermediate: "bg-secondary text-muted-foreground border-border",
  sink: "bg-red-500/15 text-red-300 border-red-500/40",
};

/** Human label for a scan record's mode. */
export const MODE_LABELS: Record<string, string> = {
  full: "Full Scan",
  recon: "Recon Only",
  injection: "Injection Test",
  static: "Static Analysis",
};
