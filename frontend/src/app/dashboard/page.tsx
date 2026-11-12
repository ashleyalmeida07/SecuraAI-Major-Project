"use client";

export const dynamic = "force-dynamic";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  Shield, Globe, Clock, Activity, ArrowRight,
  Map, Zap, Code, Bug, PlusCircle, ShieldAlert,
  BrainCircuit, Database, ShieldCheck, ChevronRight,
  TrendingUp, Target, AlertTriangle, CheckCircle2,
  FileText, Layers,
} from "lucide-react";
import { getScanHistory } from "@/lib/api";
import { DonutChart, VerticalBars, TYPE_COLORS } from "@/components/ui/report-charts";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer
} from "recharts";

type Mode = "recon" | "full" | "injection" | "static" | "llm_audit" | "baas_audit";

const MODE_META: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  recon:     { label: "Recon",      icon: Map,         color: "#22d3ee" },
  full:      { label: "Header Audit", icon: ShieldCheck, color: "#34d399" },
  injection: { label: "Injection",  icon: Zap,         color: "#f87171" },
  static:    { label: "Static",     icon: Code,        color: "#a78bfa" },
  llm_audit: { label: "LLM Audit",  icon: BrainCircuit, color: "#c084fc" },
  baas_audit:{ label: "BaaS Audit", icon: Database,    color: "#f59e0b" },
};

const SCAN_QUICK_ACTIONS = [
  {
    href: "/scan/static",
    icon: Code,
    label: "Static Analysis",
    desc: "Scan source code with 5 engines in parallel",
    accent: "#a78bfa",
    badge: "SAST",
  },
  {
    href: "/scan/recon",
    icon: Globe,
    label: "Recon",
    desc: "Map the attack surface of any live URL",
    accent: "#22d3ee",
  },
  {
    href: "/scan/full",
    icon: ShieldCheck,
    label: "Header Audit",
    desc: "Recon + full security-header audit",
    accent: "#34d399",
    badge: "Recommended",
  },
  {
    href: "/scan/injection",
    icon: Zap,
    label: "Injection Test",
    desc: "SQLi, XSS, command & path traversal",
    accent: "#f87171",
    badge: "Active",
  },
  {
    href: "/scan/llm-audit",
    icon: BrainCircuit,
    label: "LLM Audit",
    desc: "OWASP LLM Top-10 prompt-injection testing",
    accent: "#c084fc",
    badge: "OWASP LLM",
  },
  {
    href: "/scan/baas-audit",
    icon: Database,
    label: "BaaS Audit",
    desc: "Supabase / Firebase misconfiguration scan",
    accent: "#f59e0b",
  },
];

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High:     "#f97316",
  Medium:   "#eab308",
  Low:      "#3b82f6",
};

const ENDPOINT_COLORS: Record<string, string> = {
  auth_page:    "#a855f7",
  api:          "#3b82f6",
  static_asset: "#22c55e",
  dashboard:    "#f97316",
  unknown:      "#6b7280",
};

function scanMetrics(scan: any) {
  const d = scan?.data || {};
  return {
    endpoints:            d.surface_report?.total_endpoints || 0,
    headerFindings:       d.header_audit_report?.total_findings || 0,
    injectionConfirmed:   d.injection_report?.total_confirmed || 0,
    injectionTested:      d.injection_report?.total_tested || 0,
    staticVulns:          d.static_analysis_report?.triaged_findings?.length || 0,
    staticFalsePositives: d.static_analysis_report?.false_positives?.length || 0,
    staticFixes:          d.static_analysis_report?.fixes?.length || 0,
    endpointList:         d.surface_report?.endpoints || [],
    headerAllFindings:    d.header_audit_report?.findings || [],
    injectionAllFindings: d.injection_report?.findings || [],
  };
}

function StatCard({
  label, value, accent, icon: Icon, sub,
}: {
  label: string; value: number | string; accent?: string;
  icon?: React.ElementType; sub?: string;
}) {
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-border bg-card px-5 py-4">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
        {Icon && (
          <div
            className="flex h-7 w-7 items-center justify-center rounded-md border"
            style={{ borderColor: `${accent}30`, background: `${accent}12` }}
          >
            <Icon className="h-3.5 w-3.5" style={{ color: accent }} />
          </div>
        )}
      </div>
      <div className="text-3xl font-extrabold leading-none text-foreground" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {sub && <div className="text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="mb-4 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
      {children}
    </h2>
  );
}

// ── Empty-state dashboard ─────────────────────────────────────────────────────
function EmptyDashboard() {
  return (
    <div className="flex flex-col gap-8">
      {/* Welcome banner */}
      <div className="relative overflow-hidden rounded-2xl border border-border bg-card px-8 py-10">
        <div className="absolute -right-16 -top-16 h-56 w-56 rounded-full bg-primary/5 blur-3xl" />
        <div className="absolute -bottom-10 -left-10 h-40 w-40 rounded-full bg-purple-500/5 blur-2xl" />
        <div className="relative flex flex-col gap-3 max-w-xl">
          <div className="flex items-center gap-2.5">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-primary/20 bg-primary/10">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <span className="text-xs font-semibold uppercase tracking-widest text-primary">SecuraAI</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground">
            Start your first security scan
          </h2>
          <p className="text-sm leading-6 text-muted-foreground">
            Run any of the 6 scan types below — from SAST over your codebase to live BaaS misconfiguration
            testing. Results and analytics appear here automatically after each run.
          </p>
          <div className="mt-2 flex gap-3">
            <Link
              href="/scan/full"
              className="flex items-center gap-2 rounded-md bg-white px-4 py-2 text-sm font-semibold text-black transition-colors hover:bg-neutral-200"
            >
              <ShieldCheck className="h-4 w-4" /> Run Header Audit
            </Link>
            <Link
              href="/scan/static"
              className="flex items-center gap-2 rounded-md border border-border bg-secondary/60 px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-secondary"
            >
              <Code className="h-4 w-4" /> Static Analysis
            </Link>
          </div>
        </div>
      </div>

      {/* Quick-action scan cards */}
      <div>
        <SectionHeading><Layers className="h-3.5 w-3.5" /> Available Scan Types</SectionHeading>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {SCAN_QUICK_ACTIONS.map((action) => {
            const Icon = action.icon;
            return (
              <Link
                key={action.href}
                href={action.href}
                className="group relative flex flex-col gap-3 overflow-hidden rounded-xl border border-border bg-card p-5 transition-all hover:border-opacity-60 hover:shadow-lg"
                style={{ ["--hover-color" as string]: action.accent }}
              >
                <div
                  className="absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
                  style={{ background: `radial-gradient(ellipse at top left, ${action.accent}08 0%, transparent 70%)` }}
                />
                <div className="relative flex items-start justify-between">
                  <div
                    className="flex h-9 w-9 items-center justify-center rounded-lg border"
                    style={{ borderColor: `${action.accent}30`, background: `${action.accent}15` }}
                  >
                    <Icon className="h-4.5 w-4.5 h-[18px] w-[18px]" style={{ color: action.accent }} />
                  </div>
                  {action.badge && (
                    <span
                      className="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider"
                      style={{ color: action.accent, borderColor: `${action.accent}30`, background: `${action.accent}10` }}
                    >
                      {action.badge}
                    </span>
                  )}
                </div>
                <div className="relative">
                  <div className="text-sm font-semibold text-foreground">{action.label}</div>
                  <div className="mt-1 text-[13px] leading-5 text-muted-foreground">{action.desc}</div>
                </div>
                <div
                  className="relative flex items-center gap-1 text-xs font-medium opacity-0 transition-opacity duration-200 group-hover:opacity-100"
                  style={{ color: action.accent }}
                >
                  Start scan <ChevronRight className="h-3.5 w-3.5" />
                </div>
              </Link>
            );
          })}
        </div>
      </div>

      {/* How it works */}
      <div>
        <SectionHeading><Target className="h-3.5 w-3.5" /> How it works</SectionHeading>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {[
            {
              step: "01",
              icon: Target,
              title: "Enter your target",
              desc: "Paste a URL or repo path — SecuraAI auto-selects the right scan type.",
              color: "#a78bfa",
            },
            {
              step: "02",
              icon: Activity,
              title: "Watch agents run",
              desc: "A live pipeline shows every node as it runs — no black boxes.",
              color: "#22d3ee",
            },
            {
              step: "03",
              icon: FileText,
              title: "Get a full report",
              desc: "Findings, severity, OWASP mappings, and exact fix suggestions.",
              color: "#34d399",
            },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.step} className="flex flex-col gap-3 rounded-xl border border-border bg-card p-5">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs font-bold" style={{ color: item.color }}>{item.step}</span>
                  <div
                    className="flex h-7 w-7 items-center justify-center rounded-md border"
                    style={{ borderColor: `${item.color}30`, background: `${item.color}12` }}
                  >
                    <Icon className="h-3.5 w-3.5" style={{ color: item.color }} />
                  </div>
                </div>
                <div className="text-sm font-semibold text-foreground">{item.title}</div>
                <div className="text-[13px] leading-5 text-muted-foreground">{item.desc}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const router = useRouter();
  const [scans, setScans] = useState<any[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    if (!isAuthenticated()) { router.push("/login"); return; }
    getScanHistory().then(setScans).catch(console.error);
  }, [router]);

  if (!mounted) return null;

  // ── Aggregate metrics ───────────────────────────────────────────────────────
  const agg = scans.reduce((a, s) => {
    const m = scanMetrics(s);
    a.endpoints            += m.endpoints;
    a.headerFindings       += m.headerFindings;
    a.injectionConfirmed   += m.injectionConfirmed;
    a.injectionTested      += m.injectionTested;
    a.staticVulns          += m.staticVulns;
    a.staticFalsePositives += m.staticFalsePositives;
    a.staticFixes          += m.staticFixes;
    return a;
  }, { endpoints: 0, headerFindings: 0, injectionConfirmed: 0, injectionTested: 0, staticVulns: 0, staticFalsePositives: 0, staticFixes: 0 });

  const totalFindings = agg.headerFindings + agg.injectionConfirmed + agg.staticVulns;

  const scansByType = Object.entries(
    scans.reduce<Record<string, number>>((acc, s) => {
      const key = s.mode || "recon";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {})
  ).map(([key, value]) => ({
    name: MODE_META[key]?.label ?? key,
    value,
    color: MODE_META[key]?.color ?? "#6b7280",
  }));

  const findingsByCategory = [
    { name: "Header",    value: agg.headerFindings,     color: TYPE_COLORS[1] },
    { name: "Injection", value: agg.injectionConfirmed, color: TYPE_COLORS[3] },
    { name: "Static",    value: agg.staticVulns,        color: TYPE_COLORS[2] },
  ].filter(d => d.value > 0);

  const severityCounts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const endpointCounts: Record<string, number>  = {};

  scans.forEach(scan => {
    const m = scanMetrics(scan);
    [...m.headerAllFindings, ...m.injectionAllFindings].forEach((f: any) => {
      const sev = f.severity || "Low";
      severityCounts[sev] = (severityCounts[sev] || 0) + 1;
    });
    m.endpointList.forEach((ep: any) => {
      const type = ep.endpoint_type || "unknown";
      endpointCounts[type] = (endpointCounts[type] || 0) + 1;
    });
  });

  const severityData = Object.entries(severityCounts)
    .map(([name, value]) => ({ name, value }))
    .filter(d => d.value > 0);

  const endpointData = Object.entries(endpointCounts)
    .map(([key, count]) => ({ name: key.replace("_", " ").toUpperCase(), count, rawKey: key }))
    .filter(d => d.count > 0);

  const recentScans = [...scans].slice(0, 5);

  return (
    <DashboardLayout activeId="dashboard">
      <div className="mx-auto flex max-w-6xl flex-col gap-8">

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-foreground">Dashboard</h1>
            <p className="mt-1.5 text-sm text-muted-foreground">
              Overview and analytics across all your security scans.
            </p>
          </div>
          <Link
            href="/scan/full"
            className="flex shrink-0 items-center gap-2 rounded-md bg-white px-4 py-2 text-sm font-semibold text-black transition-colors hover:bg-neutral-200"
          >
            <PlusCircle className="h-4 w-4" /> New Scan
          </Link>
        </div>

        {scans.length === 0 ? (
          <EmptyDashboard />
        ) : (
          <>
            {/* Stat cards */}
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <StatCard label="Total Scans"      value={scans.length}            icon={Shield}       accent="#a78bfa" />
              <StatCard label="Endpoints Found"  value={agg.endpoints}           icon={Globe}        accent="#22d3ee" />
              <StatCard label="Vulnerabilities"  value={totalFindings}           icon={AlertTriangle} accent={totalFindings > 0 ? "#f87171" : undefined} />
              <StatCard label="Fixes Generated"  value={agg.staticFixes}         icon={CheckCircle2} accent={agg.staticFixes > 0 ? "#34d399" : undefined} />
              <StatCard label="Header Findings"  value={agg.headerFindings}      icon={ShieldAlert}  accent={agg.headerFindings > 0 ? "#f59e0b" : undefined} />
              <StatCard label="Injection Vulns"  value={agg.injectionConfirmed}  icon={Zap}          accent={agg.injectionConfirmed > 0 ? "#ef4444" : undefined} />
              <StatCard label="Static Vulns"     value={agg.staticVulns}         icon={Code}         accent={agg.staticVulns > 0 ? "#ef4444" : undefined} />
              <StatCard label="False Positives"  value={agg.staticFalsePositives} icon={Bug}         accent="#6b7280" />
            </div>

            {/* Charts row */}
            <div>
              <SectionHeading><Activity className="h-3.5 w-3.5" /> Activity Overview</SectionHeading>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-border bg-card p-5">
                  <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Scans by Type</div>
                  <VerticalBars data={scansByType} emptyLabel="No scans yet" />
                </div>
                <div className="flex flex-col rounded-xl border border-border bg-card p-5">
                  <div className="mb-3 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    <Bug className="h-3.5 w-3.5" /> Findings by Category
                  </div>
                  <DonutChart data={findingsByCategory} centerLabel="Findings" emptyLabel="No findings yet" />
                  {findingsByCategory.length > 0 && (
                    <div className="mt-3 flex flex-wrap justify-center gap-x-4 gap-y-1.5">
                      {findingsByCategory.map(d => (
                        <span key={d.name} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                          <span className="h-2 w-2 rounded-full" style={{ background: d.color }} />
                          {d.name} ({d.value})
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Analytics */}
            <div>
              <SectionHeading><ShieldAlert className="h-3.5 w-3.5" /> Vulnerability Analytics</SectionHeading>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-border bg-card p-5">
                  <div className="mb-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Findings by Severity</div>
                  {severityData.length > 0 ? (
                    <div className="h-[240px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie data={severityData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" stroke="none">
                            {severityData.map((entry, i) => (
                              <Cell key={i} fill={SEVERITY_COLORS[entry.name] || "#6b7280"} />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ backgroundColor: "#141418", borderColor: "rgba(255,255,255,0.08)", borderRadius: "8px" }} itemStyle={{ color: "#fff" }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <div className="flex h-[240px] items-center justify-center text-sm text-muted-foreground">No severity data yet</div>
                  )}
                  {severityData.length > 0 && (
                    <div className="mt-2 flex flex-wrap justify-center gap-x-4 gap-y-1">
                      {severityData.map(d => (
                        <span key={d.name} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                          <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_COLORS[d.name] }} />
                          {d.name} ({d.value})
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="rounded-xl border border-border bg-card p-5">
                  <div className="mb-4 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    <Globe className="h-3.5 w-3.5" /> Attack Surface Breakdown
                  </div>
                  {endpointData.length > 0 ? (
                    <div className="h-[240px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={endpointData} margin={{ top: 10, right: 10, left: 0, bottom: 5 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                          <XAxis dataKey="name" stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11 }} />
                          <YAxis stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11 }} allowDecimals={false} />
                          <Tooltip contentStyle={{ backgroundColor: "#141418", borderColor: "rgba(255,255,255,0.08)", borderRadius: "8px" }} itemStyle={{ color: "#fff" }} cursor={{ fill: "rgba(255,255,255,0.02)" }} />
                          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                            {endpointData.map((entry, i) => (
                              <Cell key={i} fill={ENDPOINT_COLORS[entry.rawKey] || ENDPOINT_COLORS.unknown} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <div className="flex h-[240px] items-center justify-center text-sm text-muted-foreground">No endpoint data yet</div>
                  )}
                </div>
              </div>
            </div>

            {/* Recent scans */}
            {recentScans.length > 0 && (
              <div>
                <SectionHeading><Clock className="h-3.5 w-3.5" /> Recent Scans</SectionHeading>
                <div className="flex flex-col gap-2">
                  {recentScans.map(scan => {
                    const meta = MODE_META[scan.mode] ?? MODE_META.recon;
                    const Icon = meta.icon;
                    return (
                      <div key={scan.id} className="flex items-center justify-between rounded-xl border border-border bg-card px-4 py-3 transition-colors hover:border-primary/30">
                        <div className="flex min-w-0 items-center gap-3">
                          <div
                            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border"
                            style={{ borderColor: `${meta.color}30`, background: `${meta.color}12` }}
                          >
                            <Icon className="h-4 w-4" style={{ color: meta.color }} />
                          </div>
                          <div className="min-w-0">
                            <div className="max-w-[340px] truncate text-sm font-medium text-foreground">{scan.url}</div>
                            <div className="mt-0.5 flex items-center gap-1 text-[11px] text-muted-foreground">
                              <Clock className="h-3 w-3" /> {new Date(scan.timestamp).toLocaleString()}
                              <span className="ml-1 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider" style={{ color: meta.color, borderColor: `${meta.color}30`, background: `${meta.color}10` }}>
                                {meta.label}
                              </span>
                            </div>
                          </div>
                        </div>
                        <Link
                          href={`/reports?id=${scan.id}`}
                          className="ml-4 flex shrink-0 items-center gap-1 rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium transition-colors hover:bg-secondary/70"
                        >
                          View <ArrowRight className="h-3.5 w-3.5" />
                        </Link>
                      </div>
                    );
                  })}
                </div>
                <div className="mt-4 flex justify-center">
                  <Link href="/recent" className="flex items-center gap-1.5 text-sm font-medium text-primary transition-colors hover:text-primary/80">
                    View all scans <ArrowRight className="h-4 w-4" />
                  </Link>
                </div>
              </div>
            )}

            {/* Quick-access scan cards (at bottom for users with history) */}
            <div>
              <SectionHeading><TrendingUp className="h-3.5 w-3.5" /> Run Another Scan</SectionHeading>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
                {SCAN_QUICK_ACTIONS.map((action) => {
                  const Icon = action.icon;
                  return (
                    <Link
                      key={action.href}
                      href={action.href}
                      className="group flex flex-col items-center gap-2 rounded-xl border border-border bg-card px-3 py-4 text-center transition-all hover:border-opacity-60"
                    >
                      <div
                        className="flex h-9 w-9 items-center justify-center rounded-lg border"
                        style={{ borderColor: `${action.accent}30`, background: `${action.accent}12` }}
                      >
                        <Icon className="h-4 w-4" style={{ color: action.accent }} />
                      </div>
                      <span className="text-[12px] font-medium leading-tight text-foreground">{action.label}</span>
                    </Link>
                  );
                })}
              </div>
            </div>
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
