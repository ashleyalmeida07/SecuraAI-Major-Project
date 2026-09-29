"use client";

export const dynamic = "force-dynamic";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  Shield, Globe, Clock, Activity, ArrowRight,
  Map, Zap, Code, Bug, PlusCircle, ShieldAlert
} from "lucide-react";
import { getScanHistory } from "@/lib/api";
import { DonutChart, VerticalBars, TYPE_COLORS } from "@/components/ui/report-charts";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from "recharts";

type Mode = "recon" | "full" | "injection" | "static";

const MODE_META: Record<Mode, { label: string; icon: React.ElementType; color: string }> = {
  recon:     { label: "Recon",      icon: Map,    color: "#00d4ff" },
  full:      { label: "Full Scan",  icon: Shield, color: "#a78bfa" },
  injection: { label: "Injection",  icon: Zap,    color: "#f97316" },
  static:    { label: "Static",     icon: Code,   color: "#10b981" },
};

const MODE_ORDER: Mode[] = ["recon", "full", "injection", "static"];

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

function StatTile({ label, value, accent, sub }: { label: string; value: number | string; accent?: string; sub?: string }) {
  return (
    <div className="bg-card border border-border rounded-xl px-5 py-4 flex flex-col gap-1">
      <div className="text-2xl font-extrabold text-foreground leading-none" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</div>
      {sub && <div className="text-[11px] text-muted-foreground/60">{sub}</div>}
    </div>
  );
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-1.5">
      {children}
    </h2>
  );
}

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

  // ── Aggregate metrics ──────────────────────────────────────────────────────
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

  const modeCounts = MODE_ORDER.reduce<Record<Mode, number>>((acc, m) => {
    acc[m] = scans.filter(s => s.mode === m).length;
    return acc;
  }, {} as Record<Mode, number>);

  const presentModes = MODE_ORDER.filter(m => modeCounts[m] > 0);

  // ── Chart data ────────────────────────────────────────────────────────────
  const scansByType = presentModes.map(m => ({
    name: MODE_META[m].label, value: modeCounts[m], color: MODE_META[m].color,
  }));

  const findingsByCategory = [
    { name: "Header",    value: agg.headerFindings,     color: TYPE_COLORS[1] },
    { name: "Injection", value: agg.injectionConfirmed, color: TYPE_COLORS[3] },
    { name: "Static",    value: agg.staticVulns,        color: TYPE_COLORS[2] },
  ].filter(d => d.value > 0);

  // Severity breakdown from header + injection findings
  const severityCounts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const endpointCounts: Record<string, number>  = { auth_page: 0, api: 0, static_asset: 0, dashboard: 0, unknown: 0 };

  scans.forEach(scan => {
    const m = scanMetrics(scan);
    const allFindings = [...m.headerAllFindings, ...m.injectionAllFindings];
    allFindings.forEach((f: any) => {
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
      <div className="max-w-6xl mx-auto flex flex-col gap-8">

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-foreground tracking-tight">Dashboard</h1>
            <p className="mt-2 text-sm text-muted-foreground">Overview and analytics across all your security scans.</p>
          </div>
          <Link
            href="/scan"
            className="flex items-center gap-2 bg-white text-black hover:bg-neutral-200 font-medium px-4 py-2 rounded-md transition-colors shrink-0"
          >
            <PlusCircle className="h-4 w-4" /> New Scan
          </Link>
        </div>

        {scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 bg-card border border-border rounded-xl shadow-sm">
            <Shield size={48} className="text-muted-foreground/30 mb-4" />
            <h2 className="text-xl font-semibold mb-2">No Scan History</h2>
            <p className="text-muted-foreground text-sm mb-6 text-center max-w-sm">
              You haven&apos;t run any security scans yet. Start a new scan to see results and analytics here.
            </p>
            <Link href="/scan" className="bg-white text-black hover:bg-neutral-200 font-medium px-6 py-2.5 rounded-md transition-colors">
              Run New Scan
            </Link>
          </div>
        ) : (
          <>
            {/* ── Stat Tiles ── */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatTile label="Total Scans"         value={scans.length} />
              <StatTile label="Endpoints Discovered" value={agg.endpoints + agg.injectionTested} />
              <StatTile label="Header Findings"      value={agg.headerFindings}       accent={agg.headerFindings > 0 ? "#f59e0b" : undefined} />
              <StatTile label="Injection Vulns"      value={agg.injectionConfirmed}   accent={agg.injectionConfirmed > 0 ? "#ef4444" : undefined} />
              <StatTile label="Static Vulns"         value={agg.staticVulns}          accent={agg.staticVulns > 0 ? "#ef4444" : undefined} />
              <StatTile label="False Positives"      value={agg.staticFalsePositives} />
              <StatTile label="Fixes Generated"      value={agg.staticFixes}          accent={agg.staticFixes > 0 ? "#00d4ff" : undefined} />
            </div>

            {/* ── Scan-type + Findings overview charts ── */}
            <div>
              <SectionHeading><Activity size={13} /> Activity Overview</SectionHeading>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="p-4 bg-card border border-border rounded-xl">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Scans by Type</div>
                  <VerticalBars data={scansByType} emptyLabel="No scans yet" />
                </div>
                <div className="p-4 bg-card border border-border rounded-xl flex flex-col">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                    <Bug size={13} /> Findings by Category
                  </div>
                  <DonutChart data={findingsByCategory} centerLabel="Findings" emptyLabel="No findings across scans" />
                  {findingsByCategory.length > 0 && (
                    <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 justify-center">
                      {findingsByCategory.map(d => (
                        <span key={d.name} className="flex items-center gap-1 text-[11px] text-muted-foreground">
                          <span className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                          {d.name} ({d.value})
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* ── Analytics charts ── */}
            <div>
              <SectionHeading><ShieldAlert size={13} /> Vulnerability Analytics</SectionHeading>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

                {/* Severity breakdown pie */}
                <div className="bg-card border border-border p-5 rounded-xl">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4">Findings by Severity</div>
                  {severityData.length > 0 ? (
                    <div className="h-[260px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={severityData}
                            cx="50%" cy="50%"
                            innerRadius={65} outerRadius={95}
                            paddingAngle={4}
                            dataKey="value"
                            stroke="none"
                          >
                            {severityData.map((entry, i) => (
                              <Cell key={i} fill={SEVERITY_COLORS[entry.name] || "#6b7280"} />
                            ))}
                          </Pie>
                          <Tooltip
                            contentStyle={{ backgroundColor: "#141418", borderColor: "rgba(255,255,255,0.1)", borderRadius: "8px" }}
                            itemStyle={{ color: "#fff" }}
                          />
                          <Legend verticalAlign="bottom" height={32} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <div className="h-[260px] flex items-center justify-center text-muted-foreground text-sm">
                      No severity data yet.
                    </div>
                  )}
                </div>

                {/* Attack surface bar chart */}
                <div className="bg-card border border-border p-5 rounded-xl">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-1.5">
                    <Globe size={13} /> Attack Surface Breakdown
                  </div>
                  {endpointData.length > 0 ? (
                    <div className="h-[260px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={endpointData} margin={{ top: 10, right: 10, left: 0, bottom: 5 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                          <XAxis dataKey="name" stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11 }} />
                          <YAxis stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11 }} allowDecimals={false} />
                          <Tooltip
                            contentStyle={{ backgroundColor: "#141418", borderColor: "rgba(255,255,255,0.1)", borderRadius: "8px" }}
                            itemStyle={{ color: "#fff" }}
                            cursor={{ fill: "rgba(255,255,255,0.02)" }}
                          />
                          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                            {endpointData.map((entry, i) => (
                              <Cell key={i} fill={ENDPOINT_COLORS[entry.rawKey] || ENDPOINT_COLORS.unknown} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <div className="h-[260px] flex items-center justify-center text-muted-foreground text-sm">
                      No endpoint data yet.
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* ── Recent scans quick list ── */}
            {recentScans.length > 0 && (
              <div>
                <SectionHeading><Clock size={13} /> Recent Scans</SectionHeading>
                <div className="flex flex-col gap-2">
                  {recentScans.map(scan => {
                    const mode: Mode = MODE_ORDER.includes(scan.mode) ? scan.mode : "recon";
                    const meta = MODE_META[mode];
                    const Icon = meta.icon;
                    return (
                      <div key={scan.id} className="flex items-center justify-between bg-card border border-border rounded-lg px-4 py-3 hover:border-primary/50 transition-colors">
                        <div className="flex items-center gap-3 min-w-0">
                          <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0" style={{ background: `${meta.color}1a` }}>
                            <Icon className="h-4 w-4" style={{ color: meta.color }} />
                          </div>
                          <div className="min-w-0">
                            <div className="text-sm font-medium truncate max-w-[320px]">{scan.url}</div>
                            <div className="text-[11px] text-muted-foreground flex items-center gap-1 mt-0.5">
                              <Clock className="h-3 w-3" /> {new Date(scan.timestamp).toLocaleString()}
                            </div>
                          </div>
                        </div>
                        <Link
                          href={`/reports?id=${scan.id}`}
                          className="shrink-0 flex items-center gap-1 px-3 py-1.5 rounded-md bg-secondary hover:bg-secondary/80 text-xs font-medium transition-colors ml-4"
                        >
                          View Report <ArrowRight className="h-3.5 w-3.5" />
                        </Link>
                      </div>
                    );
                  })}
                </div>
                <div className="mt-4 flex justify-center">
                  <Link href="/recent" className="flex items-center gap-2 text-sm font-medium text-primary hover:text-primary/80 transition-colors">
                    View all recent scans <ArrowRight className="w-4 h-4" />
                  </Link>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
