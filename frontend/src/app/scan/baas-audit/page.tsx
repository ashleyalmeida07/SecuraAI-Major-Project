"use client";
export const dynamic = "force-dynamic";

import React, { useState, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Activity, CheckCircle2, Database, Eye, FileText, Globe,
  HardDrive, KeyRound, Loader2, PenLine, RefreshCw, XCircle,
  Server, ShieldCheck, AlertTriangle,
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
const ACCENT = "#f59e0b";

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("token");
  if (!token || token === "null" || token === "undefined") return {};
  return { Authorization: `Bearer ${token}` };
}

const now = () =>
  new Date().toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

// ── Pipeline node definitions ─────────────────────────────────────────────────
const BAAS_AUDIT_NODES: PipelineNode[] = [
  {
    id: "detect_baas",
    name: "BaaS Detector",
    tool: "Playwright",
    icon: Globe,
    accent: ACCENT,
    description: "Crawls the target, intercepts network traffic and identifies Supabase or Firebase API calls",
    activeDesc: "Rendering page in headless browser, scanning network requests for Supabase/Firebase calls…",
    events: ["detect_baas"],
  },
  {
    id: "enumerate_tables",
    name: "Table Enumerator",
    tool: "REST API",
    icon: Database,
    accent: "#a78bfa",
    description: "Discovers exposed tables via PostgREST OpenAPI spec or Firebase JS bundle analysis",
    activeDesc: "Querying PostgREST introspection endpoint or grepping bundled JS for collection names…",
    events: ["enumerate_tables"],
  },
  {
    id: "read_access",
    name: "Read Access Test",
    tool: "HTTP (anon)",
    icon: Eye,
    accent: "#f87171",
    description: "Sends anonymous GET requests to each table — a 200 with rows means RLS is off",
    activeDesc: "Testing anonymous read access on discovered tables — checking Row Level Security…",
    events: ["read_access"],
  },
  {
    id: "write_access",
    name: "Write Access Test",
    tool: "HTTP (anon)",
    icon: PenLine,
    accent: "#ef4444",
    description: "Attempts an anonymous INSERT of a tagged probe row, then immediately DELETEs it",
    activeDesc: "Inserting probe row with anon key, then cleaning up — checking write permissions…",
    events: ["write_access"],
  },
  {
    id: "storage_test",
    name: "Storage Bucket Test",
    tool: "Storage API",
    icon: HardDrive,
    accent: "#fb923c",
    description: "Checks if storage buckets are publicly listable without authentication",
    activeDesc: "Querying storage bucket listing endpoint with anon key…",
    events: ["storage_test"],
  },
  {
    id: "auth_config",
    name: "Auth Config Test",
    tool: "Auth API",
    icon: KeyRound,
    accent: "#a78bfa",
    description: "Tests the signup flow to detect if email confirmation bypass is possible",
    activeDesc: "Attempting signup with disposable test email — checking if session is returned immediately…",
    events: ["auth_config"],
  },
  {
    id: "report_builder",
    name: "Report Builder",
    tool: "LLM + logic",
    icon: FileText,
    accent: "#34d399",
    description: "Compiles all findings into a severity-scored report with exact fix suggestions",
    activeDesc: "Building report — scoring findings, generating RLS policies and fix recommendations…",
    events: ["report_builder"],
  },
];

const BAAS_AUDIT_STAGES: PipelineStage[] = [
  {
    id: "detect",
    title: "Detection",
    caption: "Crawl the target, intercept network traffic and identify the BaaS provider and credentials.",
    nodes: [BAAS_AUDIT_NODES[0]],
  },
  {
    id: "enumerate",
    title: "Enumeration",
    caption: "Discover what tables, collections or storage buckets are exposed to anonymous callers.",
    nodes: [BAAS_AUDIT_NODES[1]],
  },
  {
    id: "testing",
    title: "Access Testing",
    caption: "Test read, write, storage and auth misconfigurations using only the public anon key.",
    nodes: [BAAS_AUDIT_NODES[2], BAAS_AUDIT_NODES[3], BAAS_AUDIT_NODES[4], BAAS_AUDIT_NODES[5]],
  },
  {
    id: "report",
    title: "Report",
    caption: "Build the final audit report with severity ratings and exact RLS policies to fix findings.",
    nodes: [BAAS_AUDIT_NODES[6]],
  },
];

// ── Test category definitions ─────────────────────────────────────────────────
const TEST_CATS = [
  { id: "read_access",  label: "Read Access",   icon: Eye,       color: "#f87171", desc: "Anonymous read on tables (RLS off)" },
  { id: "write_access", label: "Write Access",  icon: PenLine,   color: "#ef4444", desc: "Anonymous insert on tables" },
  { id: "storage_test", label: "Storage",       icon: HardDrive, color: "#fb923c", desc: "Public storage bucket listing" },
  { id: "auth_config",  label: "Auth Config",   icon: KeyRound,  color: "#a78bfa", desc: "Email confirmation bypass" },
];

// ── Types ─────────────────────────────────────────────────────────────────────
type Phase = "idle" | "scanning" | "done" | "error";

interface TestResult {
  category_id: string;
  verdict: "pass" | "fail" | "error";
  evidence: string;
  table?: string;
}
interface BaaSAuditReport {
  target_url: string;
  provider: string;
  total_checks: number;
  total_passed: number;
  total_failed: number;
  summary: string;
  test_results: TestResult[];
  errors: string[];
}

// ── Detail renderers ──────────────────────────────────────────────────────────
function DetectorDetail({ state }: { state: any }) {
  const projectUrl: string = state?.project_url || "";
  const provider: string   = state?.provider || "";
  if (!provider) return <p className="text-xs text-muted-foreground">No BaaS backend detected.</p>;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 rounded-md border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-xs">
        <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase text-amber-400">
          {provider}
        </span>
        <span className="truncate font-mono text-muted-foreground">{projectUrl || "project detected"}</span>
      </div>
      {state?.anon_key && (
        <p className="text-[11px] text-muted-foreground">
          Public anon key extracted — this key is intentionally public; the vulnerability is in what it can access.
        </p>
      )}
    </div>
  );
}

function EnumeratorDetail({ state }: { state: any }) {
  const tables: string[] = state?.tables || [];
  if (!tables.length) return <p className="text-xs text-muted-foreground">No tables discovered.</p>;
  return (
    <div className="flex flex-col gap-1.5">
      <p className="text-[11px] text-muted-foreground mb-1">{tables.length} table{tables.length > 1 ? "s" : ""} exposed via introspection:</p>
      <div className="flex flex-wrap gap-1.5">
        {tables.map((t) => (
          <span key={t} className="rounded border border-amber-500/20 bg-amber-500/5 px-2 py-0.5 font-mono text-[11px] text-amber-300">
            {t}
          </span>
        ))}
      </div>
    </div>
  );
}

function AccessTestDetail({ results, nodeId }: { results: TestResult[]; nodeId: string }) {
  const relevant = results.filter((r) => r.category_id === nodeId || r.category_id.startsWith(nodeId));
  if (!relevant.length) return <p className="text-xs text-muted-foreground">No results yet.</p>;
  return (
    <div className="flex flex-col gap-2">
      {relevant.map((r, i) => (
        <div
          key={i}
          className={`rounded-md border p-3 text-xs ${
            r.verdict === "fail"
              ? "border-red-500/25 bg-red-500/5"
              : r.verdict === "pass"
              ? "border-emerald-500/20 bg-emerald-500/5"
              : "border-border/40 bg-secondary/20"
          }`}
        >
          <div className="mb-1 flex items-center gap-2">
            {r.table && (
              <span className="font-mono text-[9px] font-bold uppercase tracking-wider text-muted-foreground">
                {r.table}
              </span>
            )}
            <span
              className={`ml-auto rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                r.verdict === "fail"
                  ? "bg-red-500/15 text-red-400"
                  : r.verdict === "pass"
                  ? "bg-emerald-500/15 text-emerald-400"
                  : "bg-secondary text-muted-foreground"
              }`}
            >
              {r.verdict}
            </span>
          </div>
          <p className="leading-relaxed text-muted-foreground">{r.evidence}</p>
        </div>
      ))}
    </div>
  );
}

function ReportDetail({ report, testResults }: { report: BaaSAuditReport; testResults: TestResult[] }) {
  const catVerdict = (catId: string) => {
    const relevant = testResults.filter((r) => r.category_id === catId);
    if (!relevant.length) return { verdict: "none" as const, evidence: "Not tested" };
    const failed = relevant.filter((r) => r.verdict === "fail");
    if (failed.length) return { verdict: "fail" as const, evidence: failed[0].evidence };
    return { verdict: "pass" as const, evidence: relevant[0]?.evidence || "All checks passed" };
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: "Total Checks",  value: report.total_checks, color: ACCENT },
          { label: "Vulnerabilities", value: report.total_failed, color: "#f87171" },
          { label: "Passed",        value: report.total_passed,  color: "#34d399" },
        ].map((s) => (
          <div key={s.label} className="rounded-lg border border-border/50 bg-secondary/20 px-3 py-2.5 text-center">
            <div className="text-xl font-bold" style={{ color: s.color }}>{s.value}</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Summary */}
      {report.summary && (
        <p className="rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2.5 text-xs leading-relaxed text-muted-foreground">
          {report.summary}
        </p>
      )}

      {/* Category rows */}
      <div className="flex flex-col gap-2">
        {TEST_CATS.map((cat) => {
          const { verdict, evidence } = catVerdict(cat.id);
          const CatIcon = cat.icon;
          return (
            <div
              key={cat.id}
              className={`flex items-start gap-3 rounded-lg border p-3 text-xs ${
                verdict === "fail"
                  ? "border-red-500/25 bg-red-500/5"
                  : verdict === "pass"
                  ? "border-emerald-500/15 bg-emerald-500/5"
                  : "border-border/40"
              }`}
            >
              <div
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border"
                style={{ borderColor: `${cat.color}30`, background: `${cat.color}10` }}
              >
                <CatIcon className="h-3.5 w-3.5" style={{ color: cat.color }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-semibold text-foreground">{cat.label}</div>
                <div className="mt-0.5 text-muted-foreground line-clamp-2">{evidence}</div>
              </div>
              <span
                className={`shrink-0 rounded px-2 py-0.5 text-[9px] font-bold uppercase ${
                  verdict === "fail"
                    ? "bg-red-500/15 text-red-400"
                    : verdict === "pass"
                    ? "bg-emerald-500/15 text-emerald-400"
                    : "bg-secondary text-muted-foreground"
                }`}
              >
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
export default function BaaSAuditPage() {
  const router = useRouter();
  useEffect(() => { if (!isAuthenticated()) router.push("/login"); }, [router]);

  const activeScan = useActiveScan();

  const [url, setUrl]                     = useState("");
  const [phase, setPhase]                 = useState<Phase>("idle");
  const [errorMsg, setErrorMsg]           = useState("");
  const [nodeStatuses, setNodeStatuses]   = useState<Record<string, NodeStatus>>({});
  const [nodeResults, setNodeResults]     = useState<Record<string, NodeResult>>({});
  const [report, setReport]               = useState<BaaSAuditReport | null>(null);
  const [testResults, setTestResults]     = useState<TestResult[]>([]);
  const [progressPct, setProgressPct]     = useState(0);
  const [activity, setActivity]           = useState("");
  const abortRef = useRef<AbortController | null>(null);

  const testResultsRef = useRef<TestResult[]>([]);
  const nodeResultsRef = useRef<Record<string, NodeResult>>({});

  const canStart = url.trim().length > 0 && phase !== "scanning";

  const NODE_ORDER = BAAS_AUDIT_NODES.map((n) => n.id);
  const TOTAL_NODES = NODE_ORDER.length;

  const markNode = (name: string, status: NodeStatus, result?: NodeResult) => {
    setNodeStatuses((prev) => {
      const next = { ...prev };
      Object.keys(next).forEach((k) => { if (next[k] === "active" && k !== name) next[k] = "done"; });
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
      if (result?.summary) activeScan.updateScan(result.summary, pct);
    }
  };

  const handleEvent = (data: any) => {
    if (data.event === "start") {
      setProgressPct(5);
      setActivity("Initialising BaaS Misconfiguration Audit…");
      const initStatuses: Record<string, NodeStatus> = {};
      BAAS_AUDIT_NODES.forEach((n) => { initStatuses[n.id] = "idle"; });
      setNodeStatuses(initStatuses);
      setNodeResults({});
      nodeResultsRef.current = {};
    } else if (data.event === "node_update" && data.node) {
      const nodeName: string = data.node;
      const state = data.state || {};
      const ts = now();

      if (state.test_results) {
        testResultsRef.current = state.test_results;
        setTestResults([...testResultsRef.current]);
      }
      if (state.baas_audit_report) setReport(state.baas_audit_report);

      let result: NodeResult | undefined;

      if (nodeName === "detect_baas") {
        const provider: string = state.provider || "";
        result = {
          timestamp: ts,
          summary: provider
            ? `Detected ${provider.toUpperCase()} backend at ${state.project_url || "unknown URL"}`
            : "No Supabase or Firebase backend found on this URL",
          metrics: provider
            ? [
                { label: "Provider", value: provider.toUpperCase(), tone: "success" },
                ...(state.anon_key ? [{ label: "Anon Key", value: "Found", tone: "warn" as const }] : []),
              ]
            : [{ label: "Provider", value: "None", tone: "neutral" }],
          handoff: provider ? `${provider} credentials → Table Enumerator` : "No BaaS detected — skipping tests",
          detail: <DetectorDetail state={state} />,
        };
      } else if (nodeName === "enumerate_tables") {
        const tables: string[] = state.tables || [];
        result = {
          timestamp: ts,
          summary: tables.length
            ? `Found ${tables.length} exposed table${tables.length > 1 ? "s" : ""}: ${tables.slice(0, 3).join(", ")}${tables.length > 3 ? "…" : ""}`
            : "No tables discovered via introspection",
          metrics: [{ label: "Tables", value: tables.length, tone: tables.length > 0 ? "warn" : "neutral" }],
          handoff: tables.length ? `${tables.length} table(s) → Access Testing` : "No tables → skipping read/write tests",
          detail: <EnumeratorDetail state={state} />,
        };
      } else if (nodeName === "read_access") {
        const relevant = testResultsRef.current.filter((r) => r.category_id === "read_access");
        const failed = relevant.filter((r) => r.verdict === "fail");
        result = {
          timestamp: ts,
          summary: relevant.length
            ? `${failed.length} table${failed.length !== 1 ? "s" : ""} readable without authentication`
            : "Testing anonymous read access…",
          metrics: [
            { label: "Tested",     value: relevant.length, tone: "neutral" },
            { label: "Vulnerable", value: failed.length,   tone: failed.length > 0 ? "danger" : "success" },
          ],
          handoff: "Read results → Write Access Test",
          detail: relevant.length > 0 ? <AccessTestDetail results={testResultsRef.current} nodeId="read_access" /> : undefined,
        };
      } else if (nodeName === "write_access") {
        const relevant = testResultsRef.current.filter((r) => r.category_id === "write_access");
        const failed = relevant.filter((r) => r.verdict === "fail");
        result = {
          timestamp: ts,
          summary: failed.length
            ? `Anonymous write succeeded on ${failed.length} table${failed.length !== 1 ? "s" : ""} — probe row cleaned up`
            : relevant.length ? "Anonymous write correctly blocked" : "Testing anonymous write access…",
          metrics: [
            { label: "Tested",     value: relevant.length, tone: "neutral" },
            { label: "Vulnerable", value: failed.length,   tone: failed.length > 0 ? "danger" : "success" },
          ],
          handoff: "Write results → Storage Bucket Test",
          detail: relevant.length > 0 ? <AccessTestDetail results={testResultsRef.current} nodeId="write_access" /> : undefined,
        };
      } else if (nodeName === "storage_test") {
        const relevant = testResultsRef.current.filter((r) => r.category_id === "storage_test");
        const failed = relevant.filter((r) => r.verdict === "fail");
        result = {
          timestamp: ts,
          summary: failed.length
            ? "Storage buckets publicly listable without authentication"
            : relevant.length ? "Storage buckets correctly locked" : "Checking storage bucket access…",
          metrics: [{ label: "Buckets Exposed", value: failed.length, tone: failed.length > 0 ? "danger" : "success" }],
          handoff: "Storage results → Auth Config Test",
        };
      } else if (nodeName === "auth_config") {
        const relevant = testResultsRef.current.filter((r) => r.category_id === "auth_config");
        const failed = relevant.filter((r) => r.verdict === "fail");
        result = {
          timestamp: ts,
          summary: failed.length
            ? "Signup returns a session token immediately — email confirmation is OFF"
            : relevant.length ? "Email confirmation is required (correctly configured)" : "Testing auth signup configuration…",
          metrics: [{ label: "Confirmation Required", value: failed.length > 0 ? "No" : "Yes", tone: failed.length > 0 ? "danger" : "success" }],
          handoff: "Auth results → Report Builder",
        };
      } else if (nodeName === "report_builder") {
        const rpt: BaaSAuditReport = state.baas_audit_report || {};
        result = {
          timestamp: ts,
          summary: rpt.total_failed != null
            ? `${rpt.total_failed} misconfiguration${rpt.total_failed !== 1 ? "s" : ""} found across ${rpt.total_checks} checks`
            : "Building report…",
          metrics: rpt.total_checks != null
            ? [
                { label: "Checks",  value: rpt.total_checks, tone: "neutral" },
                { label: "Vulns",   value: rpt.total_failed,  tone: rpt.total_failed > 0 ? "danger" : "success" },
                { label: "Passed",  value: rpt.total_passed,  tone: "success" },
              ]
            : [],
          detail: rpt.total_checks != null
            ? <ReportDetail report={rpt} testResults={testResultsRef.current} />
            : undefined,
        };
      }

      setActivity(result?.summary || nodeName);
      markNode(nodeName, "active", result);
    } else if (data.event === "complete") {
      setNodeStatuses((prev) => {
        const next = { ...prev };
        Object.keys(next).forEach((k) => { if (next[k] === "active") next[k] = "done"; });
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
    setTestResults([]);
    testResultsRef.current = [];
    nodeResultsRef.current = {};
    setNodeResults({});
    setProgressPct(5);
    setActivity("Initialising BaaS Misconfiguration Audit…");

    // ── Initialise all nodes to idle immediately so the pipeline renders ──
    const initStatuses: Record<string, NodeStatus> = {};
    BAAS_AUDIT_NODES.forEach((n) => { initStatuses[n.id] = "idle"; });
    setNodeStatuses(initStatuses);

    // ── Notify global floating banner ──
    activeScan.startScan("BaaS Audit", "/scan/baas-audit", ACCENT);

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    // Track whether we got a proper "complete" event from the backend.
    // If the stream closes without one, we know the backend endpoint is missing.
    let receivedComplete = false;

    try {
      const res = await fetch(`${API_BASE}/scan/stream/baas-audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({ url: url.trim() }),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(
        res.status === 404
          ? "BaaS Audit endpoint not found — the backend needs to be updated. Run: git pull && restart uvicorn on EC2."
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
            if (parsed.event === "complete") receivedComplete = true;
            handleEvent(parsed);
          } catch { /* skip malformed */ }
        }
      }
      // Only mark done if the backend sent a proper complete event
      if (receivedComplete) {
        // already handled inside handleEvent
      } else {
        // Stream ended prematurely — backend endpoint likely not deployed
        const msg = "Stream ended without a completion signal. The backend may not have the BaaS Audit endpoint yet — deploy the latest code to EC2.";
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
    setTestResults([]);
    testResultsRef.current = [];
    nodeResultsRef.current = {};
    setErrorMsg("");
    setProgressPct(0);
    setActivity("");
    activeScan.resetScan();
  };

  const showPipeline = phase !== "idle";
  const scanComplete = phase === "done";

  return (
    <DashboardLayout activeId="scan-baas-audit">
      <div className="mx-auto flex max-w-5xl flex-col gap-6">
        <ScanTabs />

        {/* Flow header */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2.5">
            <Database className="h-6 w-6" style={{ color: ACCENT }} />
            <h2 className="text-xl font-semibold tracking-tight text-foreground">BaaS Misconfiguration Audit</h2>
          </div>
          <p className="text-sm leading-6 text-muted-foreground">
            Detects Supabase and Firebase backends on a target URL and tests for misconfigured Row Level Security,
            open storage buckets, and weak auth settings.
          </p>
        </div>

        {/* Input + facts */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="flex flex-col gap-5 lg:col-span-7">

            {/* Target URL */}
            <div>
              <Label htmlFor="baas-url" className="font-medium">Target URL</Label>
              <div className="relative mt-2">
                <Globe className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="baas-url"
                  type="url"
                  className="h-11 bg-background pl-10 focus-visible:ring-primary"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleStart()}
                  disabled={phase === "scanning"}
                />
              </div>
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
                  <><Activity className="mr-2 h-4 w-4" />Start BaaS Audit</>
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
              <p className="text-[13px] font-semibold text-foreground">Tests BaaS backends for common misconfigurations</p>
              <ul className="mt-3 flex flex-col gap-2">
                {[
                  "Auto-detects Supabase and Firebase from network traffic",
                  "Tests Row Level Security (RLS) on every discovered table",
                  "Attempts anonymous write with immediate self-cleanup",
                  "Checks storage bucket listing and auth configuration",
                  "Suggests exact RLS policies and security rules to fix issues",
                ].map((b) => (
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

            {/* Stage-based pipeline — same ScanPipeline component as LLM Audit / Recon / Injection */}
            <ScanPipeline
              stages={BAAS_AUDIT_STAGES}
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

        {/* No BaaS detected */}
        {scanComplete && report && !report.provider && (
          <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-card py-16 text-center">
            <Server className="mb-4 h-10 w-10 text-muted-foreground/30" />
            <h3 className="mb-2 text-base font-semibold text-foreground">No BaaS Backend Detected</h3>
            <p className="max-w-sm text-sm text-muted-foreground">
              No Supabase or Firebase signals were found in the target&apos;s network traffic or bundled JavaScript.
            </p>
          </div>
        )}

        {/* Summary stats when done */}
        {scanComplete && report && report.provider && (
          <div className="flex flex-col gap-4">
            {/* Provider badge */}
            <div className="flex items-center gap-2">
              <span className="rounded-md border border-amber-500/20 bg-amber-500/10 px-3 py-1.5 text-xs font-bold tracking-wider text-amber-400">
                {report.provider.toUpperCase()} DETECTED
              </span>
              {report.total_failed === 0 ? (
                <span className="flex items-center gap-1.5 rounded-md border border-emerald-500/20 bg-emerald-500/5 px-3 py-1.5 text-xs font-semibold text-emerald-400">
                  <ShieldCheck className="h-3.5 w-3.5" />No misconfigurations found
                </span>
              ) : (
                <span className="flex items-center gap-1.5 rounded-md border border-red-500/20 bg-red-500/5 px-3 py-1.5 text-xs font-semibold text-red-400">
                  <AlertTriangle className="h-3.5 w-3.5" />{report.total_failed} misconfiguration{report.total_failed !== 1 ? "s" : ""} found
                </span>
              )}
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: "Total Checks",         value: report.total_checks, color: ACCENT,    bg: "bg-amber-500/10",   border: "border-amber-500/20" },
                { label: "Vulnerabilities Found", value: report.total_failed, color: "#f87171", bg: "bg-red-500/10",     border: "border-red-500/20" },
                { label: "Checks Passed",         value: report.total_passed, color: "#34d399", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
              ].map((s) => (
                <div key={s.label} className={`${s.bg} border ${s.border} rounded-xl px-5 py-4 text-center`}>
                  <div className="text-3xl font-bold leading-none" style={{ color: s.color }}>{s.value}</div>
                  <div className="mt-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">{s.label}</div>
                </div>
              ))}
            </div>

            {/* Executive summary */}
            {report.summary && (
              <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-5">
                <p className="mb-2 text-xs font-semibold uppercase tracking-wider" style={{ color: ACCENT }}>
                  Executive Summary
                </p>
                <p className="text-sm leading-relaxed text-muted-foreground">{report.summary}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
