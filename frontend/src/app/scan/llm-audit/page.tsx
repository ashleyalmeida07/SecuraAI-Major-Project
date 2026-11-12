"use client";
export const dynamic = "force-dynamic";

import React, { useState, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Activity, BrainCircuit, CheckCircle2, FileText, Globe,
  Loader2, Server, ShieldAlert, ShieldCheck, Swords, XCircle,
  RefreshCw, Cpu, Zap, Database,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { isAuthenticated } from "@/utils/auth";
import { ScanTabs } from "@/components/scan/scan-tabs";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
const ACCENT = "#c084fc";

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("token");
  if (!token || token === "null" || token === "undefined") return {};
  return { Authorization: `Bearer ${token}` };
}

// ── Node metadata ─────────────────────────────────────────────────────────────
const NODE_META: Record<string, { label: string; tool: string; icon: React.ElementType; desc: string }> = {
  detector:       { label: "AI Surface Detector", tool: "Playwright",      icon: Globe,       desc: "Crawls the target looking for chat widgets, AI API endpoints and streaming responses" },
  connect:        { label: "Connect Node",         tool: "HTTP / DOM",     icon: Server,      desc: "Determines how to interact with the detected AI surface" },
  attacker:       { label: "Attack Loop",          tool: "Prompt library", icon: Swords,      desc: "Sends adversarial prompts across all 5 OWASP LLM categories" },
  judge:          { label: "Judge Node",           tool: "LLM",            icon: ShieldAlert, desc: "An LLM decides pass or fail for each reply, citing evidence" },
  mutation:       { label: "Mutation Node",        tool: "LLM",            icon: RefreshCw,   desc: "Rephrases blocked prompts (rephrase, encode, role-play) and retries" },
  report_builder: { label: "Report Builder",       tool: "LLM + logic",    icon: FileText,    desc: "Builds the OWASP LLM Top-10 scorecard with an executive summary" },
};

// ── OWASP category definitions ────────────────────────────────────────────────
const OWASP_CATS = [
  { id: "llm01", owasp: "LLM01", label: "Prompt Injection",      categories: ["system_prompt_extraction", "instruction_override"], color: "#f87171" },
  { id: "llm02", owasp: "LLM02", label: "Insecure Output",       categories: ["indirect_injection"],                               color: "#fb923c" },
  { id: "llm06", owasp: "LLM06", label: "Sensitive Information", categories: ["pii_leakage"],                                      color: "#fbbf24" },
  { id: "llm08", owasp: "LLM08", label: "Excessive Agency",      categories: ["tool_abuse"],                                       color: "#a78bfa" },
];

// ── Types ─────────────────────────────────────────────────────────────────────
type Phase = "idle" | "scanning" | "done" | "error";
type NodeState = "pending" | "running" | "done" | "error";

interface NodeStatus { name: string; state: NodeState }
interface AttackResult {
  category_id: string; owasp: string; category_name: string;
  prompt: string; response_text: string;
  verdict: "pass" | "fail" | "error";
  evidence: string; deterministic: boolean; mutation_round: number;
}
interface LLMAuditReport {
  target_url: string; ai_surfaces_found: number; connect_method: string;
  total_attacks: number; total_passed: number; total_failed: number;
  owasp_mapping: Record<string, string[]>; severity_breakdown: Record<string, number>;
  summary: string; errors: string[];
}

// ── Status dot ────────────────────────────────────────────────────────────────
function StatusDot({ state }: { state: NodeState }) {
  if (state === "running") return (
    <span className="relative flex h-2.5 w-2.5 shrink-0">
      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75" />
      <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-purple-400" />
    </span>
  );
  if (state === "done")  return <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-emerald-500" />;
  if (state === "error") return <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-red-500" />;
  return <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-border" />;
}

// ── Pipeline row ──────────────────────────────────────────────────────────────
function PipelineRow({ status }: { status: NodeStatus }) {
  const meta = NODE_META[status.name] ?? { label: status.name, tool: "", icon: Cpu, desc: "" };
  const Icon = meta.icon;
  const isRunning = status.state === "running";
  const isDone    = status.state === "done";

  return (
    <div className={`flex items-center gap-4 rounded-lg border px-4 py-3 transition-all duration-300 ${
      isRunning ? "border-purple-500/30 bg-purple-500/5" :
      isDone    ? "border-border/50 bg-card/40" :
                  "border-border/30 bg-transparent"
    }`}>
      <StatusDot state={status.state} />
      <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md border ${
        isRunning ? "border-purple-500/30 bg-purple-500/10 text-purple-400" :
        isDone    ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-500" :
                    "border-border/40 text-muted-foreground/40"
      }`}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="flex-1 min-w-0">
        <div className={`text-sm font-medium ${isRunning ? "text-foreground" : isDone ? "text-foreground/80" : "text-muted-foreground/50"}`}>
          {meta.label}
        </div>
        <div className="text-[11px] text-muted-foreground truncate">{meta.tool}</div>
      </div>
      <span className={`text-[11px] font-medium capitalize ${
        isRunning ? "text-purple-400" :
        isDone    ? "text-emerald-500" :
        status.state === "error" ? "text-red-400" :
                    "text-muted-foreground/30"
      }`}>
        {status.state}
      </span>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function LLMAuditPage() {
  const router = useRouter();
  useEffect(() => { if (!isAuthenticated()) router.push("/login"); }, [router]);

  const [url, setUrl]                       = useState("");
  const [hint, setHint]                     = useState("");
  const [phase, setPhase]                   = useState<Phase>("idle");
  const [errorMsg, setErrorMsg]             = useState("");
  const [nodeStatuses, setNodeStatuses]     = useState<NodeStatus[]>([]);
  const [report, setReport]                 = useState<LLMAuditReport | null>(null);
  const [attackResults, setAttackResults]   = useState<AttackResult[]>([]);
  const [progressPct, setProgressPct]       = useState(0);
  const [activity, setActivity]             = useState("");
  const abortRef = useRef<AbortController | null>(null);

  const canStart = url.trim().length > 0 && phase !== "scanning";

  const handleEvent = (data: any) => {
    if (data.event === "start") {
      setNodeStatuses(Object.keys(NODE_META).map(n => ({ name: n, state: "pending" })));
      setProgressPct(5);
      setActivity("Initialising LLM Prompt-Injection Audit…");
    } else if (data.event === "node_update" && data.node) {
      const nodeName = data.node as string;
      setActivity(NODE_META[nodeName]?.desc ?? nodeName);
      setNodeStatuses(prev => {
        // mark all prior running nodes as done, set current to running
        const updated = prev.map(n =>
          n.name === nodeName ? { ...n, state: "running" as NodeState }
          : n.state === "running" ? { ...n, state: "done" as NodeState }
          : n
        );
        if (!updated.find(n => n.name === nodeName)) {
          updated.push({ name: nodeName, state: "running" });
        }
        return updated;
      });
      const doneCount = Object.keys(NODE_META).indexOf(nodeName) + 1;
      setProgressPct(Math.round((doneCount / Object.keys(NODE_META).length) * 90) + 5);

      if (data.state?.llm_audit_report) setReport(data.state.llm_audit_report);
      if (data.state?.attack_results)   setAttackResults(data.state.attack_results);
    } else if (data.event === "complete") {
      setNodeStatuses(prev => prev.map(n => n.state === "running" ? { ...n, state: "done" } : n));
      setProgressPct(100);
      setActivity("Audit complete.");
      setPhase("done");
    } else if (data.event === "error") {
      setErrorMsg(data.message ?? "Unknown error");
      setPhase("error");
    }
  };

  const handleStart = async () => {
    if (!canStart) return;
    setPhase("scanning");
    setErrorMsg("");
    setNodeStatuses([]);
    setReport(null);
    setAttackResults([]);
    setProgressPct(0);
    setActivity("");

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      const res = await fetch(`${API_BASE}/scan/stream/llm-audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({ url: url.trim(), endpoint_hint: hint.trim() || undefined }),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`Request failed: ${res.statusText}`);
      if (!res.body) throw new Error("No response body");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const j = line.slice(6).trim();
          if (j) try { handleEvent(JSON.parse(j)); } catch { /* skip */ }
        }
      }
      setPhase("done");
    } catch (err: unknown) {
      if ((err as { name?: string }).name === "AbortError") return;
      setErrorMsg(err instanceof Error ? err.message : "Unknown error");
      setPhase("error");
    }
  };

  const handleReset = () => {
    abortRef.current?.abort();
    setPhase("idle"); setNodeStatuses([]); setReport(null);
    setAttackResults([]); setErrorMsg(""); setProgressPct(0); setActivity("");
  };

  // OWASP verdict helper
  const owaspVerdict = (cats: string[]) => {
    const relevant = attackResults.filter(r => cats.includes(r.category_id));
    if (!relevant.length) return { verdict: "none" as const, evidence: "Not tested in this run" };
    const failed = relevant.filter(r => r.verdict === "fail");
    if (failed.length) return { verdict: "fail" as const, evidence: failed[0].evidence || "Vulnerability confirmed" };
    return { verdict: "pass" as const, evidence: relevant[0]?.evidence || "All attacks were blocked" };
  };

  const noSurface = report?.ai_surfaces_found === 0 && report?.connect_method === "none";
  const showPipeline = phase !== "idle" && nodeStatuses.length > 0;

  return (
    <DashboardLayout activeId="scan-llm-audit">
      <div className="mx-auto flex max-w-5xl flex-col gap-6">
        <ScanTabs />

        {/* Flow header */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2.5">
            <BrainCircuit className="h-6 w-6" style={{ color: ACCENT }} />
            <h2 className="text-xl font-semibold tracking-tight text-foreground">LLM Prompt-Injection Audit</h2>
          </div>
          <p className="text-sm leading-6 text-muted-foreground">
            Detects AI surfaces on a target URL and runs OWASP LLM Top-10 attack categories —
            system-prompt extraction, jailbreaks, PII leakage, indirect injection, and tool abuse.
          </p>
        </div>

        {/* Input + facts */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="flex flex-col gap-5 lg:col-span-7">

            {/* Target URL */}
            <div>
              <Label htmlFor="llm-url" className="font-medium">Target URL</Label>
              <div className="relative mt-2">
                <Globe className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="llm-url"
                  type="url"
                  className="h-11 bg-background pl-10 focus-visible:ring-primary"
                  placeholder="https://example.com"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleStart()}
                  disabled={phase === "scanning"}
                />
              </div>
            </div>

            {/* AI Endpoint hint */}
            <div>
              <Label htmlFor="llm-hint" className="font-medium">
                AI Endpoint{" "}
                <span className="font-normal text-muted-foreground">(optional)</span>
              </Label>
              <div className="relative mt-2">
                <Cpu className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="llm-hint"
                  type="url"
                  className="h-11 bg-background pl-10 focus-visible:ring-primary"
                  placeholder="https://example.com/api/chat"
                  value={hint}
                  onChange={e => setHint(e.target.value)}
                  disabled={phase === "scanning"}
                />
              </div>
              <p className="mt-1.5 text-xs text-muted-foreground">
                If the auto-detector misses the AI surface, paste its API endpoint here.
              </p>
            </div>

            {/* Action buttons */}
            <div className="flex gap-3">
              <Button
                onClick={handleStart}
                disabled={!canStart}
                className="flex-1 font-medium bg-white text-black hover:bg-neutral-200 transition-colors"
              >
                {phase === "scanning" ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Auditing…</>
                ) : (
                  <><Activity className="mr-2 h-4 w-4" />Start LLM Audit</>
                )}
              </Button>
              {phase !== "idle" && (
                <Button variant="outline" onClick={handleReset} className="font-medium">
                  Reset
                </Button>
              )}
            </div>

            {/* Error */}
            {phase === "error" && errorMsg && (
              <div className="flex items-center gap-3 rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-destructive">
                <XCircle className="h-5 w-5 shrink-0" />
                <span className="text-sm font-medium">{errorMsg}</span>
              </div>
            )}
          </div>

          {/* Facts panel */}
          <div className="lg:col-span-5">
            <div className="rounded-xl border border-border/60 bg-card/60 p-5">
              <p className="text-[13px] font-semibold text-foreground">Covers all 5 OWASP LLM Top-10 attack classes</p>
              <ul className="mt-3 flex flex-col gap-2">
                {[
                  "Auto-detects chat widgets, /api/chat endpoints and streaming AI calls",
                  "Sends adversarial prompts: system-prompt extraction, jailbreaks, PII leakage",
                  "LLM judge with deterministic canary-phrase checks for certainty",
                  "Mutation engine rephrases blocked prompts and retries up to 3×",
                  "Findings mapped to OWASP LLM01, LLM02, LLM06, LLM08",
                ].map(b => (
                  <li key={b} className="flex items-start gap-2 text-[13px] text-muted-foreground">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" style={{ color: ACCENT }} />
                    {b}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Live pipeline */}
        {showPipeline && (
          <div className="flex flex-col gap-4">

            {/* Progress bar */}
            <div className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-4">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-sm font-semibold">
                  {phase === "done" ? (
                    <><CheckCircle2 className="h-4 w-4 text-emerald-500" />Audit Complete</>
                  ) : phase === "error" ? (
                    <><XCircle className="h-4 w-4 text-red-500" />Audit Failed</>
                  ) : (
                    <><Loader2 className="h-4 w-4 animate-spin text-primary" />Running Agents</>
                  )}
                </span>
                <span className="text-sm font-bold text-primary tabular-nums">{progressPct}%</span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
                <div
                  className="h-full rounded-full transition-all duration-700 ease-out"
                  style={{ width: `${progressPct}%`, background: ACCENT }}
                />
              </div>
              {activity && (
                <p className="border-l-2 pl-3 font-mono text-xs text-muted-foreground" style={{ borderColor: ACCENT }}>
                  {activity}
                </p>
              )}
            </div>

            {/* Node pipeline */}
            <div className="rounded-xl border border-border/50 bg-card p-4">
              <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Agent Pipeline</p>
              <div className="flex flex-col gap-2">
                {nodeStatuses.map(ns => <PipelineRow key={ns.name} status={ns} />)}
              </div>
            </div>

            {/* Post-scan actions */}
            {phase === "done" && (
              <div className="flex gap-4 pt-1">
                <Button variant="outline" className="flex-1 font-semibold" onClick={handleReset}>
                  <RefreshCw className="mr-2 h-4 w-4" />Scan Again
                </Button>
              </div>
            )}
          </div>
        )}

        {/* Results */}
        {phase === "done" && report && (
          <>
            {noSurface ? (
              /* No AI surface found */
              <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-card py-16 text-center">
                <Database className="h-10 w-10 text-muted-foreground/30 mb-4" />
                <h3 className="text-base font-semibold text-foreground mb-2">No AI Surface Detected</h3>
                <p className="text-sm text-muted-foreground max-w-sm">
                  No AI chat widgets or API endpoints were found. If you know the endpoint,
                  paste it in the AI Endpoint field and re-run.
                </p>
              </div>
            ) : (
              <>
                {/* Stats */}
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { label: "Total Attacks",         value: report.total_attacks, color: ACCENT,      bg: "bg-purple-500/10",  border: "border-purple-500/20" },
                    { label: "Vulnerabilities Found", value: report.total_failed,  color: "#f87171",   bg: "bg-red-500/10",     border: "border-red-500/20" },
                    { label: "Attacks Blocked",       value: report.total_passed,  color: "#34d399",   bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
                  ].map(s => (
                    <div key={s.label} className={`${s.bg} border ${s.border} rounded-xl px-5 py-4 text-center`}>
                      <div className="text-3xl font-bold leading-none" style={{ color: s.color }}>{s.value}</div>
                      <div className="mt-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* Executive summary */}
                {report.summary && (
                  <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-5">
                    <p className="mb-2 text-xs font-semibold uppercase tracking-wider" style={{ color: ACCENT }}>
                      Executive Summary
                    </p>
                    <p className="text-sm leading-relaxed text-muted-foreground">{report.summary}</p>
                  </div>
                )}

                {/* OWASP scorecard */}
                <div>
                  <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    OWASP LLM Top-10 Scorecard
                  </p>
                  <div className="flex flex-col gap-3">
                    {OWASP_CATS.map(cat => {
                      const { verdict, evidence } = owaspVerdict(cat.categories);
                      const isFail = verdict === "fail";
                      const isPass = verdict === "pass";
                      return (
                        <div
                          key={cat.id}
                          className={`flex items-start gap-4 rounded-xl border p-5 transition-colors ${
                            isFail ? "border-red-500/25 bg-red-500/5"
                            : isPass ? "border-emerald-500/15 bg-emerald-500/5"
                            : "border-border/50 bg-card/60"
                          }`}
                        >
                          {/* OWASP badge */}
                          <div className="flex h-9 shrink-0 items-center rounded-md border border-purple-500/25 bg-purple-500/10 px-2.5 font-mono text-xs font-bold" style={{ color: ACCENT }}>
                            {cat.owasp}
                          </div>

                          {/* Content */}
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-semibold text-foreground">{cat.label}</div>
                            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{evidence}</p>
                          </div>

                          {/* Verdict */}
                          <div className={`shrink-0 rounded-md px-3 py-1.5 text-xs font-bold tracking-wider ${
                            isFail ? "bg-red-500/15 text-red-400"
                            : isPass ? "bg-emerald-500/15 text-emerald-400"
                            : "bg-muted/30 text-muted-foreground"
                          }`}>
                            {isFail ? "FAIL" : isPass ? "PASS" : "N/A"}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Severity breakdown */}
                {Object.keys(report.severity_breakdown ?? {}).length > 0 && (
                  <div className="rounded-xl border border-border/50 bg-card p-5">
                    <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                      <ShieldCheck className="h-3.5 w-3.5" /> Severity Breakdown
                    </p>
                    <div className="flex flex-wrap gap-3">
                      {Object.entries(report.severity_breakdown).map(([sev, count]) => {
                        const c = sev === "Critical" ? "#ef4444" : sev === "High" ? "#f97316" : sev === "Medium" ? "#eab308" : "#3b82f6";
                        return (
                          <div key={sev} className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm">
                            <span className="h-2 w-2 rounded-full" style={{ background: c }} />
                            <span className="font-medium text-foreground">{count}</span>
                            <span className="text-muted-foreground">{sev}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
