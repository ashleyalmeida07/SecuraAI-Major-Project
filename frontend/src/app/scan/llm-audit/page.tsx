"use client";
export const dynamic = "force-dynamic";

import React, { useState, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Activity, BrainCircuit, CheckCircle2, FileText, Globe,
  Loader2, Server, ShieldAlert, ShieldCheck, Swords, XCircle,
  RefreshCw, Cpu, Database, Shield, AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { ScanPipeline } from "@/components/ui/scan-pipeline";
import type { PipelineStage, PipelineNode, NodeResult, NodeStatus } from "@/components/ui/scan-pipeline";
import { isAuthenticated } from "@/utils/auth";
import { ScanTabs } from "@/components/scan/scan-tabs";
import { useActiveScan } from "@/contexts/active-scan-context";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
const ACCENT = "#c084fc";

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("token");
  if (!token || token === "null" || token === "undefined") return {};
  return { Authorization: `Bearer ${token}` };
}

const now = () =>
  new Date().toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

// ── Pipeline node definitions ─────────────────────────────────────────────────
const LLM_AUDIT_NODES: PipelineNode[] = [
  {
    id: "detector",
    name: "AI Surface Detector",
    tool: "Playwright",
    icon: Globe,
    accent: ACCENT,
    description: "Crawls the target looking for chat widgets, AI API endpoints and streaming responses",
    activeDesc: "Rendering page in headless browser, intercepting network requests for AI endpoints…",
    events: ["detector"],
  },
  {
    id: "connect",
    name: "Connect Node",
    tool: "HTTP / DOM",
    icon: Server,
    accent: "#a78bfa",
    description: "Determines how to interact with the detected AI surface — API or DOM",
    activeDesc: "Analysing detected surfaces and establishing the best connection method…",
    events: ["connect"],
  },
  {
    id: "attacker",
    name: "Attack Loop",
    tool: "Prompt library",
    icon: Swords,
    accent: "#f87171",
    description: "Sends adversarial prompts across all 5 OWASP LLM categories",
    activeDesc: "Sending adversarial prompts — system-prompt extraction, jailbreaks, PII leakage…",
    events: ["attacker"],
  },
  {
    id: "judge",
    name: "Judge Node",
    tool: "LLM",
    icon: ShieldAlert,
    accent: "#f59e0b",
    description: "An LLM decides pass or fail for each reply, with deterministic canary-phrase checks first",
    activeDesc: "LLM evaluating response — checking for canary phrases, refusals, system-prompt dumps…",
    events: ["judge"],
  },
  {
    id: "mutation",
    name: "Mutation Node",
    tool: "LLM",
    icon: RefreshCw,
    accent: "#fb923c",
    description: "Rephrases blocked prompts (rephrase, encode, role-play framing) and retries up to 3×",
    activeDesc: "Generating mutated prompt variant — rephrasing, encoding or adding roleplay framing…",
    events: ["mutation"],
  },
  {
    id: "advance_index",
    name: "Advance Loop",
    tool: "Router",
    icon: Activity,
    accent: "#64748b",
    description: "Advances to the next attack category and resets mutation counter",
    activeDesc: "Moving to next OWASP attack category…",
    events: ["advance_index"],
  },
  {
    id: "report_builder",
    name: "Report Builder",
    tool: "LLM + logic",
    icon: FileText,
    accent: "#34d399",
    description: "Builds the OWASP LLM Top-10 scorecard with an executive summary",
    activeDesc: "Compiling attack results, scoring by OWASP category, writing executive summary…",
    events: ["report_builder"],
  },
];

const LLM_AUDIT_STAGES: PipelineStage[] = [
  {
    id: "detect",
    title: "AI Surface Detection",
    caption: "Crawl the target, intercept network traffic and detect chat widgets or AI API endpoints.",
    nodes: [LLM_AUDIT_NODES[0], LLM_AUDIT_NODES[1]],
  },
  {
    id: "attack",
    title: "Attack Loop",
    caption: "Send adversarial prompts, judge each response, mutate and retry blocked attempts.",
    nodes: [LLM_AUDIT_NODES[2], LLM_AUDIT_NODES[3], LLM_AUDIT_NODES[4], LLM_AUDIT_NODES[5]],
  },
  {
    id: "report",
    title: "Report",
    caption: "Build the OWASP LLM Top-10 scorecard with severity ratings and executive summary.",
    nodes: [LLM_AUDIT_NODES[6]],
  },
];

// ── OWASP category definitions ─────────────────────────────────────────────────
const OWASP_CATS = [
  { id: "llm01", owasp: "LLM01", label: "Prompt Injection",      categories: ["system_prompt_extraction", "instruction_override"], color: "#f87171" },
  { id: "llm02", owasp: "LLM02", label: "Insecure Output",       categories: ["indirect_injection"],                               color: "#fb923c" },
  { id: "llm06", owasp: "LLM06", label: "Sensitive Information", categories: ["pii_leakage"],                                      color: "#fbbf24" },
  { id: "llm08", owasp: "LLM08", label: "Excessive Agency",      categories: ["tool_abuse"],                                       color: "#a78bfa" },
];

// ── Types ──────────────────────────────────────────────────────────────────────
type Phase = "idle" | "scanning" | "done" | "error";

interface AttackResult {
  category_id: string; owasp: string; category_name: string;
  prompt: string; response_text: string;
  verdict: "pass" | "fail" | "error" | "pending";
  evidence: string; deterministic: boolean; mutation_round: number;
}
interface LLMAuditReport {
  target_url: string; ai_surfaces_found: number; connect_method: string;
  total_attacks: number; total_passed: number; total_failed: number;
  owasp_mapping: Record<string, string[]>; severity_breakdown: Record<string, number>;
  categories_tested: any[];
  summary: string; errors: string[];
}

// ── Detail renderers for each node ────────────────────────────────────────────
function DetectorDetail({ state }: { state: any }) {
  const surfaces: any[] = state?.ai_surfaces || [];
  if (!surfaces.length) return <p className="text-xs text-muted-foreground">No AI surfaces detected.</p>;
  return (
    <div className="flex flex-col gap-1.5">
      {surfaces.map((s, i) => (
        <div key={i} className="flex items-center gap-2 rounded-md border border-border/50 bg-secondary/30 px-3 py-2 text-xs">
          <span className="rounded border border-purple-500/30 bg-purple-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase text-purple-400">{s.type}</span>
          <span className="truncate font-mono text-muted-foreground">{s.url || s.selector || "—"}</span>
          <span className="ml-auto shrink-0 rounded bg-secondary px-1.5 py-0.5 text-[9px] text-muted-foreground">{s.confidence}</span>
        </div>
      ))}
    </div>
  );
}

function AttackDetail({ results }: { results: AttackResult[] }) {
  if (!results?.length) return <p className="text-xs text-muted-foreground">No attacks sent yet.</p>;
  const last5 = results.slice(-5);
  return (
    <div className="flex flex-col gap-2">
      {last5.map((r, i) => (
        <div key={i} className={`rounded-md border p-3 text-xs ${r.verdict === "fail" ? "border-red-500/25 bg-red-500/5" : r.verdict === "pass" ? "border-emerald-500/20 bg-emerald-500/5" : "border-border/40 bg-secondary/20"}`}>
          <div className="mb-1.5 flex items-center gap-2">
            <span className="font-mono text-[9px] font-bold uppercase tracking-wider text-muted-foreground">{r.category_name}</span>
            {r.mutation_round > 0 && <span className="rounded bg-orange-500/10 px-1 text-[9px] text-orange-400">Mutation {r.mutation_round}</span>}
            <span className={`ml-auto rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${r.verdict === "fail" ? "bg-red-500/15 text-red-400" : r.verdict === "pass" ? "bg-emerald-500/15 text-emerald-400" : "bg-secondary text-muted-foreground"}`}>
              {r.verdict}
            </span>
          </div>
          <p className="mb-1 leading-relaxed text-muted-foreground line-clamp-2">{r.prompt}</p>
          {r.evidence && <p className="border-l-2 border-purple-500/40 pl-2 text-[11px] italic text-muted-foreground/80">{r.evidence}</p>}
        </div>
      ))}
    </div>
  );
}

function ReportDetail({ report, attackResults }: { report: LLMAuditReport; attackResults: AttackResult[] }) {
  return (
    <div className="flex flex-col gap-4">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: "Total Attacks",   value: report.total_attacks, color: ACCENT },
          { label: "Vulnerabilities", value: report.total_failed,  color: "#f87171" },
          { label: "Blocked",         value: report.total_passed,  color: "#34d399" },
        ].map(s => (
          <div key={s.label} className="rounded-lg border border-border/50 bg-secondary/20 px-3 py-2.5 text-center">
            <div className="text-xl font-bold" style={{ color: s.color }}>{s.value}</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{s.label}</div>
          </div>
        ))}
      </div>
      {/* Summary */}
      {report.summary && (
        <p className="rounded-md border border-purple-500/20 bg-purple-500/5 px-3 py-2.5 text-xs leading-relaxed text-muted-foreground">
          {report.summary}
        </p>
      )}
      {/* OWASP rows */}
      <div className="flex flex-col gap-2">
        {OWASP_CATS.map(cat => {
          const relevant = attackResults.filter(r => cat.categories.includes(r.category_id));
          const failed = relevant.filter(r => r.verdict === "fail");
          const verdict = !relevant.length ? "none" : failed.length ? "fail" : "pass";
          const evidence = failed[0]?.evidence || relevant[0]?.evidence || (verdict === "none" ? "Not tested" : "All attacks blocked");
          return (
            <div key={cat.id} className={`flex items-start gap-3 rounded-lg border p-3 text-xs ${verdict === "fail" ? "border-red-500/25 bg-red-500/5" : verdict === "pass" ? "border-emerald-500/15 bg-emerald-500/5" : "border-border/40"}`}>
              <span className="shrink-0 rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold" style={{ color: ACCENT, borderColor: `${ACCENT}30`, background: `${ACCENT}10` }}>{cat.owasp}</span>
              <div className="flex-1 min-w-0">
                <div className="font-semibold text-foreground">{cat.label}</div>
                <div className="mt-0.5 text-muted-foreground line-clamp-2">{evidence}</div>
              </div>
              <span className={`shrink-0 rounded px-2 py-0.5 text-[9px] font-bold uppercase ${verdict === "fail" ? "bg-red-500/15 text-red-400" : verdict === "pass" ? "bg-emerald-500/15 text-emerald-400" : "bg-secondary text-muted-foreground"}`}>
                {verdict === "none" ? "N/A" : verdict.toUpperCase()}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function LLMAuditPage() {
  const router = useRouter();
  useEffect(() => { if (!isAuthenticated()) router.push("/login"); }, [router]);

  const activeScan = useActiveScan();

  const [url, setUrl]                       = useState("");
  const [hint, setHint]                     = useState("");
  const [phase, setPhase]                   = useState<Phase>("idle");
  const [errorMsg, setErrorMsg]             = useState("");
  const [nodeStatuses, setNodeStatuses]     = useState<Record<string, NodeStatus>>({});
  const [nodeResults, setNodeResults]       = useState<Record<string, NodeResult>>({});
  const [report, setReport]                 = useState<LLMAuditReport | null>(null);
  const [attackResults, setAttackResults]   = useState<AttackResult[]>([]);
  const [progressPct, setProgressPct]       = useState(0);
  const [activity, setActivity]             = useState("");
  const abortRef = useRef<AbortController | null>(null);

  // Keep mutable refs for use inside streaming closure
  const attackResultsRef = useRef<AttackResult[]>([]);
  const nodeResultsRef   = useRef<Record<string, NodeResult>>({});

  const canStart = url.trim().length > 0 && phase !== "scanning";

  const NODE_ORDER = LLM_AUDIT_NODES.map(n => n.id);
  const TOTAL_NODES = NODE_ORDER.length;

  const markNode = (name: string, status: NodeStatus, result?: NodeResult) => {
    setNodeStatuses(prev => {
      const next = { ...prev };
      // Mark any other running node as done
      Object.keys(next).forEach(k => { if (next[k] === "active" && k !== name) next[k] = "done"; });
      next[name] = status;
      return next;
    });
    if (result) {
      nodeResultsRef.current = { ...nodeResultsRef.current, [name]: result };
      setNodeResults({ ...nodeResultsRef.current });
    }
    const idx = NODE_ORDER.indexOf(name);
    if (idx >= 0) {
      const pct = Math.round(((idx + 1) / TOTAL_NODES) * 90) + 5;
      setProgressPct(pct);
      // sync global banner
      if (result?.summary) activeScan.updateScan(result.summary, pct);
    }
  };

  const handleEvent = (data: any, rawState: Record<string, any>) => {
    if (data.event === "start") {
      setProgressPct(5);
      setActivity("Initialising LLM Prompt-Injection Audit…");
      const initStatuses: Record<string, NodeStatus> = {};
      LLM_AUDIT_NODES.forEach(n => { initStatuses[n.id] = "idle"; });
      setNodeStatuses(initStatuses);
      setNodeResults({});
      nodeResultsRef.current = {};
    } else if (data.event === "node_update" && data.node) {
      const nodeName: string = data.node;
      const state = data.state || {};
      const ts = now();

      // Accumulate attack results
      if (state.attack_results) {
        attackResultsRef.current = state.attack_results;
        setAttackResults([...attackResultsRef.current]);
      }
      if (state.llm_audit_report) setReport(state.llm_audit_report);

      // Build NodeResult for this node
      let result: NodeResult | undefined;

      if (nodeName === "detector") {
        const surfaces: any[] = state.ai_surfaces || [];
        result = {
          timestamp: ts,
          summary: surfaces.length
            ? `Found ${surfaces.length} AI surface${surfaces.length > 1 ? "s" : ""} — ${state.connect_method || "detecting connection method"}`
            : "No AI surfaces found on this URL",
          metrics: [
            { label: "Surfaces", value: surfaces.length, tone: surfaces.length > 0 ? "success" : "neutral" },
            ...(state.connect_method ? [{ label: "Method", value: state.connect_method, tone: "info" as const }] : []),
          ],
          handoff: surfaces.length ? `${surfaces.length} surface(s) → Connect Node` : "No surface detected — skipping attack loop",
          detail: surfaces.length > 0 ? <DetectorDetail state={state} /> : undefined,
        };
      } else if (nodeName === "connect") {
        result = {
          timestamp: ts,
          summary: state.connect_method === "api"
            ? `API mode — will POST to ${state.connect_config?.url || "detected endpoint"}`
            : state.connect_method === "dom"
            ? `DOM mode — typing into chat widget (selector: ${state.connect_config?.selector || "input"})`
            : "No connection — running simulated attacks",
          metrics: state.connect_method ? [{ label: "Mode", value: state.connect_method.toUpperCase(), tone: state.connect_method === "none" ? "warn" : "success" }] : [],
          handoff: "Connection established → Attack Loop",
        };
      } else if (nodeName === "attacker") {
        const all: AttackResult[] = attackResultsRef.current;
        const pending = all.filter(r => r.verdict === "pending");
        const last = all[all.length - 1];
        result = {
          timestamp: ts,
          summary: last ? `Sent: "${last.prompt.slice(0, 70)}…"` : "Sending attack prompt…",
          metrics: [
            { label: "Sent", value: all.filter(r => r.verdict !== "pending").length, tone: "neutral" },
            { label: "Pending", value: pending.length, tone: pending.length > 0 ? "warn" : "neutral" },
          ],
          handoff: "Response → Judge Node",
          detail: all.length > 0 ? <AttackDetail results={all} /> : undefined,
        };
      } else if (nodeName === "judge") {
        const all: AttackResult[] = attackResultsRef.current;
        const failed = all.filter(r => r.verdict === "fail");
        const passed = all.filter(r => r.verdict === "pass");
        const last = all.filter(r => r.verdict !== "pending").slice(-1)[0];
        result = {
          timestamp: ts,
          summary: last
            ? `${last.verdict.toUpperCase()}: ${last.evidence?.slice(0, 80) || last.verdict}`
            : "Evaluating response…",
          metrics: [
            { label: "Failed", value: failed.length, tone: failed.length > 0 ? "danger" : "neutral" },
            { label: "Passed", value: passed.length, tone: passed.length > 0 ? "success" : "neutral" },
            ...(last?.deterministic ? [{ label: "Deterministic", value: "Yes", tone: "info" as const }] : []),
          ],
          detail: all.length > 0 ? <AttackDetail results={all} /> : undefined,
        };
      } else if (nodeName === "mutation") {
        const count = state.mutation_count || 0;
        result = {
          timestamp: ts,
          summary: `Mutation round ${count} — rephrasing blocked prompt`,
          metrics: [{ label: "Mutations", value: count, tone: "warn" }],
          handoff: "Mutated prompt → Attack Loop",
        };
      } else if (nodeName === "advance_index") {
        const idx = state.attack_index || 0;
        const categoryNames = ["System Prompt Extraction", "Instruction Override", "PII Leakage", "Tool Abuse", "Indirect Injection"];
        result = {
          timestamp: ts,
          summary: idx < categoryNames.length
            ? `Advancing to category ${idx + 1}: ${categoryNames[idx]}`
            : "All categories complete",
          metrics: [{ label: "Category", value: `${idx}/${categoryNames.length}`, tone: "info" }],
        };
      } else if (nodeName === "report_builder") {
        const rpt: LLMAuditReport = state.llm_audit_report || {};
        result = {
          timestamp: ts,
          summary: rpt.total_failed != null
            ? `${rpt.total_failed} vulnerabilities found across ${rpt.total_attacks} attacks`
            : "Building report…",
          metrics: rpt.total_attacks != null ? [
            { label: "Attacks",  value: rpt.total_attacks, tone: "neutral" },
            { label: "Vulns",    value: rpt.total_failed,  tone: rpt.total_failed > 0 ? "danger" : "success" },
            { label: "Blocked",  value: rpt.total_passed,  tone: "success" },
          ] : [],
          detail: rpt.total_attacks != null
            ? <ReportDetail report={rpt} attackResults={attackResultsRef.current} />
            : undefined,
        };
      }

      setActivity(result?.summary || nodeName);
      markNode(nodeName, "active", result);

    } else if (data.event === "complete") {
      // Mark all running nodes as done, finalize report node
      setNodeStatuses(prev => {
        const next = { ...prev };
        Object.keys(next).forEach(k => { if (next[k] === "active") next[k] = "done"; });
        return next;
      });
      setProgressPct(100);
      setActivity("Audit complete.");
      setPhase("done");
      activeScan.finishScan("done");
    } else if (data.event === "error") {
      setErrorMsg(data.message ?? "Unknown error");
      setPhase("error");
      activeScan.finishScan("error");
    }
  };

  const handleStart = async () => {
    if (!canStart) return;
    setPhase("scanning");
    setErrorMsg("");
    setReport(null);
    setAttackResults([]);
    attackResultsRef.current = [];
    nodeResultsRef.current = {};
    setNodeResults({});
    setProgressPct(5);
    setActivity("Initialising LLM Prompt-Injection Audit…");

    // ── Initialise all nodes to idle immediately so the pipeline renders ──
    const initStatuses: Record<string, NodeStatus> = {};
    LLM_AUDIT_NODES.forEach((n) => { initStatuses[n.id] = "idle"; });
    setNodeStatuses(initStatuses);

    // ── Notify global banner ──
    activeScan.startScan("LLM Audit", "/scan/llm-audit", ACCENT);

    // ── Notify global banner ──
    activeScan.startScan("LLM Audit", "/scan/llm-audit", ACCENT);

    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const rawState: Record<string, any> = {};

    // Track whether backend sent a proper "complete" event
    let receivedComplete = false;

    try {
      const res = await fetch(`${API_BASE}/scan/stream/llm-audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({ url: url.trim(), endpoint_hint: hint.trim() || undefined }),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(
        res.status === 404
          ? "LLM Audit endpoint not found — the backend needs to be updated. Run: git pull && restart uvicorn on EC2."
          : `Request failed: ${res.statusText}`
      );
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
          if (!j) continue;
          try {
            const parsed = JSON.parse(j);
            if (parsed.event === "node_update" && parsed.state) {
              Object.assign(rawState, parsed.state);
            }
            if (parsed.event === "complete") receivedComplete = true;
            handleEvent(parsed, rawState);
          } catch { /* skip malformed */ }
        }
      }
      if (!receivedComplete) {
        const msg = "Stream ended without a completion signal. The backend may not have the LLM Audit endpoint yet — deploy the latest code to EC2.";
        setErrorMsg(msg);
        setPhase("error");
        activeScan.finishScan("error");
      }
    } catch (err: unknown) {
      if ((err as { name?: string }).name === "AbortError") return;
      const msg = err instanceof Error ? err.message : "Unknown error";
      setErrorMsg(msg);
      setPhase("error");
      activeScan.finishScan("error");
    }
  };

  const handleReset = () => {
    abortRef.current?.abort();
    setPhase("idle");
    setNodeStatuses({});
    setNodeResults({});
    setReport(null);
    setAttackResults([]);
    attackResultsRef.current = [];
    nodeResultsRef.current = {};
    setErrorMsg("");
    setProgressPct(0);
    setActivity("");
    activeScan.resetScan();
  };

  const showPipeline = phase !== "idle";
  const scanComplete = phase === "done";

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

            {/* Progress header */}
            <div className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-4">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-sm font-semibold">
                  {scanComplete ? (
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

            {/* Stage-based pipeline — same component as Recon/Injection/Header pages */}
            <ScanPipeline
              stages={LLM_AUDIT_STAGES}
              statuses={nodeStatuses}
              results={nodeResults}
            />

            {/* Post-scan actions */}
            {scanComplete && (
              <div className="flex gap-4 pt-1">
                <Button variant="outline" className="flex-1 font-semibold" onClick={handleReset}>
                  <RefreshCw className="mr-2 h-4 w-4" />Scan Again
                </Button>
              </div>
            )}
          </div>
        )}

        {/* Full report when done and no AI surface */}
        {scanComplete && report && report.ai_surfaces_found === 0 && (
          <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-card py-16 text-center">
            <Database className="mb-4 h-10 w-10 text-muted-foreground/30" />
            <h3 className="mb-2 text-base font-semibold text-foreground">No AI Surface Detected</h3>
            <p className="max-w-sm text-sm text-muted-foreground">
              No AI chat widgets or API endpoints were found. If you know the endpoint,
              paste it in the AI Endpoint field and re-run.
            </p>
          </div>
        )}

        {/* Summary stats when done and surface found */}
        {scanComplete && report && report.ai_surfaces_found > 0 && (
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: "Total Attacks",         value: report.total_attacks, color: ACCENT,    bg: "bg-purple-500/10",  border: "border-purple-500/20" },
              { label: "Vulnerabilities Found",  value: report.total_failed,  color: "#f87171", bg: "bg-red-500/10",     border: "border-red-500/20" },
              { label: "Attacks Blocked",        value: report.total_passed,  color: "#34d399", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
            ].map(s => (
              <div key={s.label} className={`${s.bg} border ${s.border} rounded-xl px-5 py-4 text-center`}>
                <div className="text-3xl font-bold leading-none" style={{ color: s.color }}>{s.value}</div>
                <div className="mt-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">{s.label}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
