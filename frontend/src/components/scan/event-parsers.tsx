"use client";

/**
 * Turns a backend graph node's state update into something renderable.
 *
 * Every flow streams `{event: "node_update", node, state}` over SSE, where
 * `state` is whatever that node returned. Each parser here reads one node's
 * shape and produces a `NodeResult` — a one-line summary, a few metric chips,
 * an expandable detail block, and what the node hands to the next one.
 *
 * Split out of the scan page so the four per-flow tabs share one implementation
 * rather than each carrying a copy.
 */

import React from "react";
import { FileSearch, Link2, Tag } from "lucide-react";
import type { NodeResult } from "@/components/ui/scan-pipeline";
import { severityStyle, taintChain, toolMeta } from "@/lib/static-analysis";

/** Running totals the triage card needs, since the backend streams one finding at a time. */
export interface TriageAcc {
  confirmed: number;
  discarded: number;
  done: number;
  total: number;
}

const SEVERITY_TEXT: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-violet-400",
};

function StatGrid({ items }: { items: { label: string; value: React.ReactNode; tone?: string }[] }) {
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      {items.map((item) => (
        <div key={item.label} className="rounded bg-muted/60 p-2 text-center">
          <div className={`text-base font-bold tabular-nums ${item.tone || "text-foreground"}`}>
            {item.value}
          </div>
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{item.label}</div>
        </div>
      ))}
    </div>
  );
}

function Prose({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded border border-border/50 bg-muted/40 p-3 text-[11px] leading-relaxed text-muted-foreground">
      {children}
    </div>
  );
}

// ── URL-driven flows (recon / full / injection) ──────────────────────────────

function parseCrawler(state: any): NodeResult {
  const urls = state?.discovered_urls || [];
  return {
    summary: `Discovered ${urls.length} URL${urls.length !== 1 ? "s" : ""} on the target`,
    metrics: [{ label: "URLs", value: urls.length, tone: "info" }],
    detail: (
      <div className="flex flex-col gap-2">
        <p className="text-[11px] text-muted-foreground">Endpoints found during the crawl:</p>
        <div className="flex max-h-36 flex-col gap-1 overflow-y-auto">
          {urls.slice(0, 12).map((u: any, i: number) => (
            <div key={i} className="flex items-center gap-2 font-mono text-[11px]">
              <Link2 className="h-3 w-3 shrink-0 text-blue-400" />
              <span className="truncate text-blue-300">{u.url || u}</span>
              {u.method && (
                <span className="rounded bg-muted px-1 text-muted-foreground">{u.method}</span>
              )}
            </div>
          ))}
          {urls.length > 12 && (
            <p className="text-[11px] text-muted-foreground">…and {urls.length - 12} more</p>
          )}
        </div>
      </div>
    ),
    handoff: `${urls.length} raw URLs → Classifier Node`,
  };
}

function parseClassifier(state: any): NodeResult {
  const endpoints = state?.classified_endpoints || [];
  const types: Record<string, number> = {};
  endpoints.forEach((e: any) => {
    const t = e.endpoint_type || "unknown";
    types[t] = (types[t] || 0) + 1;
  });

  return {
    summary: `Classified ${endpoints.length} endpoint${endpoints.length !== 1 ? "s" : ""} into ${
      Object.keys(types).length
    } type${Object.keys(types).length !== 1 ? "s" : ""}`,
    metrics: [
      { label: "Endpoints", value: endpoints.length },
      { label: "Types", value: Object.keys(types).length, tone: "info" },
    ],
    detail: (
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(types).map(([type, count]) => (
            <div key={type} className="flex items-center gap-1 rounded bg-muted px-2 py-1 text-[11px]">
              <Tag className="h-3 w-3 text-primary" />
              <span className="font-medium capitalize">{type.replace(/_/g, " ")}</span>
              <span className="text-muted-foreground">×{count}</span>
            </div>
          ))}
        </div>
        <div className="flex max-h-32 flex-col gap-1 overflow-y-auto">
          {endpoints.slice(0, 8).map((e: any, i: number) => (
            <div key={i} className="flex items-center gap-2 font-mono text-[11px]">
              <span className="truncate text-muted-foreground">{e.url}</span>
              <span className="shrink-0 font-medium text-green-400">{e.endpoint_type}</span>
            </div>
          ))}
        </div>
      </div>
    ),
    handoff: `${endpoints.length} classified endpoints → Surface Report Node`,
  };
}

function parseSurfaceReport(state: any): NodeResult {
  const report = state?.surface_report || {};
  const total = report.total_endpoints || 0;
  const endpoints = report.endpoints || [];
  const types: Record<string, number> = {};
  endpoints.forEach((e: any) => {
    const t = e.endpoint_type || "unknown";
    types[t] = (types[t] || 0) + 1;
  });

  return {
    summary: `Built the attack-surface map — ${total} endpoint${total !== 1 ? "s" : ""}`,
    metrics: [{ label: "Endpoints", value: total, tone: "info" }],
    detail: (
      <div className="flex flex-col gap-2">
        <StatGrid
          items={[
            { label: "Total", value: total },
            ...Object.entries(types)
              .slice(0, 3)
              .map(([k, v]) => ({ label: k.replace(/_/g, " "), value: String(v) })),
          ]}
        />
        {typeof report.summary === "string" && report.summary && <Prose>{report.summary}</Prose>}
      </div>
    ),
    handoff: "Surface report ready",
  };
}

function parseHeaderFetcher(state: any): NodeResult {
  const results = state?.header_results || [];
  return {
    summary: `Fetched headers from ${results.length} endpoint${results.length !== 1 ? "s" : ""}`,
    metrics: [{ label: "Responses", value: results.length }],
    detail: (
      <div className="flex max-h-36 flex-col gap-1 overflow-y-auto">
        {results.slice(0, 8).map((r: any, i: number) => (
          <div key={i} className="rounded border border-border/50 bg-muted/50 p-2 text-[11px]">
            <div className="truncate font-mono text-blue-300">{r.url}</div>
            <div className="mt-1 text-muted-foreground">
              {r.headers &&
                Object.keys(r.headers)
                  .slice(0, 4)
                  .map((h) => (
                    <span key={h} className="mr-2">
                      {h}
                    </span>
                  ))}
            </div>
          </div>
        ))}
      </div>
    ),
    handoff: `${results.length} header sets → Rule Checker Node`,
  };
}

function parseRuleChecker(state: any): NodeResult {
  const checklist = state?.checklist_results || [];
  const passes = checklist.filter((c: any) => c.status === "pass").length;
  const failed = checklist.filter((c: any) => c.status === "fail").length;
  const missing = checklist.filter((c: any) => c.status === "missing").length;
  const problems = checklist.filter((c: any) => c.status !== "pass");

  return {
    summary: `Evaluated ${checklist.length} check${checklist.length !== 1 ? "s" : ""} — ${passes} pass, ${failed + missing} need attention`,
    metrics: [
      { label: "pass", value: passes, tone: "success" as const },
      { label: "fail", value: failed, tone: "danger" as const },
      { label: "missing", value: missing, tone: "warn" as const },
    ].filter((m) => m.value > 0) as NodeResult["metrics"],
    detail: (
      <div className="flex flex-col gap-1.5">
        {problems.slice(0, 6).map((c: any, i: number) => (
          <div key={i} className="rounded border border-border/50 p-2 text-[11px]">
            <span className="font-medium text-amber-400">[{String(c.status).toUpperCase()}]</span>
            <span className="ml-1 text-muted-foreground">{c.header_name}</span>
            {c.description && (
              <p className="mt-0.5 line-clamp-2 text-muted-foreground">{c.description}</p>
            )}
          </div>
        ))}
      </div>
    ),
    handoff: `${problems.length} of ${checklist.length} checks → Severity Scorer (passes skip the LLM)`,
  };
}

function parseSeverityScorer(state: any): NodeResult {
  const report = state?.audit_report || {};
  const scored = state?.scored_findings || [];
  const configured = report.configured_count ?? 0;
  const gradedTotal = report.graded_total ?? 0;
  return {
    summary: `${configured}/${gradedTotal} controls configured · AI scored ${scored.length} problem${scored.length !== 1 ? "s" : ""}`,
    metrics: [
      { label: "Configured", value: `${configured}/${gradedTotal}`, tone: "success" as const },
      { label: "Need attention", value: report.total_findings ?? scored.length, tone: "danger" as const },
    ] as NodeResult["metrics"],
    detail: report.summary ? <Prose>{report.summary}</Prose> : undefined,
    handoff: "Final audit report generated",
  };
}

function parsePayloadGenerator(state: any): NodeResult {
  const cases = state?.test_cases || [];
  const types = ["sqli", "xss", "command_injection", "path_traversal"];
  return {
    summary: `Generated ${cases.length} test payload${cases.length !== 1 ? "s" : ""}`,
    metrics: types
      .map((t) => ({
        label: t.replace(/_/g, " "),
        value: cases.filter((c: any) => c.injection_type === t).length,
        tone: "warn" as const,
      }))
      .filter((m) => m.value > 0),
    handoff: `${cases.length} payloads → Injector Node`,
  };
}

function parseInjector(state: any): NodeResult {
  const results = state?.injection_results || [];
  const anomalies = results.filter(
    (r: any) => r.payload_reflected || r.sql_error_found || r.status_diff,
  ).length;
  return {
    summary: `Tested ${results.length} payload${results.length !== 1 ? "s" : ""} — ${anomalies} anomal${
      anomalies !== 1 ? "ies" : "y"
    }`,
    metrics: [
      { label: "Tested", value: results.length },
      { label: "Anomalies", value: anomalies, tone: "warn" },
      { label: "Clean", value: results.length - anomalies, tone: "success" },
    ],
    handoff: `${anomalies} anomalies → Response Analyzer`,
  };
}

function parseResponseAnalyzer(state: any): NodeResult {
  const confirmed = state?.confirmed_findings || [];
  const discarded = state?.discarded || [];
  return {
    summary: `AI confirmed ${confirmed.length}, discarded ${discarded.length}`,
    metrics: [
      { label: "Confirmed", value: confirmed.length, tone: "danger" },
      { label: "Discarded", value: discarded.length },
    ],
    detail: (
      <div className="flex flex-col gap-1.5">
        {confirmed.slice(0, 5).map((f: any, i: number) => (
          <div key={i} className="rounded border border-border/50 p-2 text-[11px]">
            <span className="font-medium text-red-400">[{String(f.severity || "").toUpperCase()}]</span>
            <span className="ml-1 text-muted-foreground">
              {f.injection_type} on {f.parameter}
            </span>
          </div>
        ))}
      </div>
    ),
    handoff: `${confirmed.length} confirmed → Report Builder`,
  };
}

function parseInjectionReport(state: any): NodeResult {
  const report = state?.injection_report || {};
  return {
    summary: `Built the injection report — ${report.total_confirmed || 0} vulnerabilit${
      (report.total_confirmed || 0) !== 1 ? "ies" : "y"
    }`,
    metrics: [
      { label: "Tested", value: report.total_tested ?? 0 },
      { label: "Confirmed", value: report.total_confirmed ?? 0, tone: "danger" },
      { label: "Discarded", value: report.total_discarded ?? 0 },
    ],
    detail: report.summary ? <Prose>{report.summary}</Prose> : undefined,
    handoff: "Final injection report generated",
  };
}

/** Parse one node update from a URL-driven flow. */
export function parseFlowNode(node: string, state: any): NodeResult {
  switch (node) {
    case "crawler": return parseCrawler(state);
    case "classifier": return parseClassifier(state);
    case "surface_report": return parseSurfaceReport(state);
    case "header_fetcher": return parseHeaderFetcher(state);
    case "rule_checker": return parseRuleChecker(state);
    case "severity_scorer": return parseSeverityScorer(state);
    case "payload_generator": return parsePayloadGenerator(state);
    case "injector": return parseInjector(state);
    case "response_analyzer": return parseResponseAnalyzer(state);
    case "report_builder": return parseInjectionReport(state);
    default:
      return { summary: `${node} completed` };
  }
}

// ── Static analysis flow ─────────────────────────────────────────────────────

function parseScanner(tool: string, state: any): NodeResult {
  const status = (state?.tool_status || {})[tool] || {};
  const meta = toolMeta(tool);
  const count = status.finding_count ?? 0;
  const skipped = String(status.note || "").toLowerCase().includes("skipped");

  const summary = skipped
    ? "Skipped for this run"
    : status.ok
    ? `${count} raw finding${count !== 1 ? "s" : ""} in ${(status.duration_s ?? 0).toFixed(1)}s`
    : `Unavailable — ${status.note || "tool did not run"}`;

  return {
    summary,
    metrics: [
      { label: "Raw", value: count, tone: count > 0 ? "danger" : "success" },
      { label: "Time", value: `${(status.duration_s ?? 0).toFixed(1)}s` },
      ...(status.used_sample ? [{ label: "Sample data", value: "yes", tone: "warn" as const }] : []),
    ],
    detail: (
      <div className="flex flex-col gap-2 text-[11px]">
        <p className="text-muted-foreground">{meta.blurb}</p>
        {status.note && (
          <p className={status.ok ? "text-muted-foreground" : "text-amber-400"}>{status.note}</p>
        )}
        {status.used_sample && (
          <p className="rounded border border-amber-500/30 bg-amber-500/10 p-2 text-amber-400">
            This binary was not found on the server&apos;s PATH, so representative sample findings
            were substituted to keep the merge, RAG and triage stages meaningful. Install the tool
            for real results.
          </p>
        )}
      </div>
    ),
  };
}

function parseMerge(state: any): NodeResult {
  const stats = state?.merge_stats || {};
  const safe = (state?.safe_patterns || []).length;
  const unique = stats.total_after_dedup ?? 0;

  return {
    summary: `${unique} unique finding${unique !== 1 ? "s" : ""} after removing ${
      stats.duplicates_removed ?? 0
    } duplicate${(stats.duplicates_removed ?? 0) !== 1 ? "s" : ""}`,
    metrics: [
      { label: "Raw", value: stats.total_raw ?? 0 },
      { label: "Unique", value: unique, tone: "info" },
      { label: "Multi-tool", value: stats.multi_tool_confirmed ?? 0, tone: "danger" },
      { label: "Taint paths", value: stats.with_taint_path ?? 0, tone: "success" },
    ],
    detail: (
      <div className="flex flex-col gap-2">
        <p className="text-[11px] text-muted-foreground">
          Raw findings per tool before the merge:
        </p>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(stats.raw_per_tool || {}).map(([tool, count]) => (
            <div key={tool} className="flex items-center gap-1 rounded bg-muted px-2 py-1 text-[11px]">
              <FileSearch className="h-3 w-3" style={{ color: toolMeta(tool).color }} />
              <span className="font-medium">{tool}</span>
              <span className="text-muted-foreground">{String(count)}</span>
            </div>
          ))}
        </div>
        {safe > 0 && (
          <p className="rounded border border-emerald-500/30 bg-emerald-500/10 p-2 text-[11px] text-emerald-400">
            {safe} existing security control{safe !== 1 ? "s" : ""} detected in the codebase — these
            are reported as positive evidence, not problems.
          </p>
        )}
      </div>
    ),
    handoff: `${unique} findings → Context Retrieval`,
  };
}

function parseRetrieveContext(state: any): NodeResult {
  const findings = state?.merged_findings || [];
  const enriched = findings.filter((f: any) => (f.context || []).length > 0).length;
  const top = findings.find((f: any) => (f.context || []).length > 0);

  return {
    summary: `Enriched ${enriched}/${findings.length} finding${
      findings.length !== 1 ? "s" : ""
    } with known-vulnerable patterns`,
    metrics: [
      { label: "Matched", value: enriched, tone: "info" },
      { label: "No match", value: findings.length - enriched },
    ],
    detail: top ? (
      <div className="flex flex-col gap-2 text-[11px]">
        <p className="text-muted-foreground">
          Closest match for <span className="font-mono text-violet-300">{top.rule_id}</span>:
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-violet-300">
            {top.context[0].vuln_type}
          </span>
          <span className="text-muted-foreground">{top.context[0].framework}</span>
          <span className="font-mono text-muted-foreground">
            similarity {top.context[0].score}
          </span>
        </div>
        <pre className="max-h-32 overflow-auto rounded bg-muted/60 p-2 font-mono text-[10px] text-muted-foreground">
          {top.context[0].similar_vulnerable_code}
        </pre>
      </div>
    ) : undefined,
    handoff: `${findings.length} enriched findings → AI Triage`,
  };
}

function parseTriage(state: any, acc: TriageAcc): NodeResult {
  const total = acc.total || state?.triage_progress?.total || 0;
  const current = state?.current_finding;

  return {
    summary:
      acc.done >= total && total > 0
        ? `Triaged ${total} finding${total !== 1 ? "s" : ""} — ${acc.confirmed} confirmed, ${
            acc.discarded
          } ruled out`
        : `Triaging — ${acc.confirmed} confirmed, ${acc.discarded} ruled out (${acc.done}/${total})`,
    progress: { done: acc.done, total },
    metrics: [
      { label: "Confirmed", value: acc.confirmed, tone: "danger" },
      { label: "Ruled out", value: acc.discarded },
    ],
    detail: current ? (
      <div className="flex flex-col gap-2 text-[11px]">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded border px-1.5 py-0.5 ${severityStyle(current.final_severity)}`}>
            {String(current.final_severity || "").toUpperCase()}
          </span>
          <span className="font-medium">{current.category}</span>
          <span className="font-mono text-cyan-300">
            {current.file}:{current.line}
          </span>
          <span
            className={
              current.verdict === "false_positive" ? "text-muted-foreground" : "text-red-400"
            }
          >
            {current.verdict === "false_positive" ? "ruled out" : "confirmed"}
          </span>
        </div>
        {current.triage_reason && <p className="text-muted-foreground">{current.triage_reason}</p>}
        {current.taint_path && (
          <p className="font-mono text-[10px] text-emerald-400">
            {taintChain(current.taint_path)}
          </p>
        )}
      </div>
    ) : undefined,
    handoff: `${acc.confirmed} confirmed → Fix Generator`,
  };
}

function parseFixGenerator(state: any): NodeResult {
  const fixes = state?.fixes || [];
  const grounded = fixes.filter((f: any) => f.grounded_in && f.grounded_in !== "none").length;

  return {
    summary: `Generated ${fixes.length} remediation${fixes.length !== 1 ? "s" : ""}`,
    metrics: [
      { label: "Fixes", value: fixes.length, tone: "success" },
      { label: "Grounded", value: grounded, tone: "info" },
    ],
    detail: fixes.length ? (
      <div className="flex flex-col gap-1.5">
        {fixes.slice(0, 6).map((f: any, i: number) => (
          <div key={i} className="flex items-center gap-2 font-mono text-[11px]">
            <span className="text-violet-400">
              {f.file}:{f.line}
            </span>
            <span className="truncate text-muted-foreground">{f.rule_id}</span>
          </div>
        ))}
      </div>
    ) : undefined,
    handoff: `${fixes.length} fixes → Report Builder`,
  };
}

function parseStaticReport(state: any): NodeResult {
  const report = state?.static_report || {};
  return {
    summary: `Report ready — ${report.confirmed_count ?? 0} confirmed, ${
      report.fixes_count ?? 0
    } fix${(report.fixes_count ?? 0) !== 1 ? "es" : ""}`,
    metrics: [
      { label: "Unique", value: report.total_after_merge ?? 0 },
      { label: "Confirmed", value: report.confirmed_count ?? 0, tone: "danger" },
      { label: "Ruled out", value: report.ruled_out_count ?? 0 },
      { label: "Taint paths", value: report.with_taint_path_count ?? 0, tone: "success" },
    ],
    detail: report.summary ? <Prose>{report.summary}</Prose> : undefined,
    handoff: "Final SAST report generated",
  };
}

/** Parse one node update from the static analysis flow, keyed by pipeline node id. */
export function parseStaticNode(pipelineId: string, state: any, acc: TriageAcc): NodeResult {
  switch (pipelineId) {
    case "run_semgrep": return parseScanner("semgrep", state);
    case "run_bearer": return parseScanner("bearer", state);
    case "run_osv_scanner": return parseScanner("osv-scanner", state);
    case "run_gitleaks": return parseScanner("gitleaks", state);
    case "run_codeql": return parseScanner("codeql", state);
    case "merge_findings": return parseMerge(state);
    case "retrieve_context": return parseRetrieveContext(state);
    case "triage": return parseTriage(state, acc);
    case "fix_generator": return parseFixGenerator(state);
    case "report_builder": return parseStaticReport(state);
    default:
      return { summary: `${pipelineId} completed` };
  }
}
