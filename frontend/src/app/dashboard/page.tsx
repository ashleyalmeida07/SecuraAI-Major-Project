"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  Shield, Globe, Clock, Activity, ArrowRight, Trash2,
  Map, Zap, Code, FolderGit2, Bug, LayoutList, PlusCircle
} from "lucide-react";
import { DonutChart, VerticalBars, TYPE_COLORS } from "@/components/ui/report-charts";

type Mode = "recon" | "full" | "injection" | "static";
type Filter = "all" | Mode;

const MODE_META: Record<Mode, { label: string; icon: React.ElementType; color: string }> = {
  recon: { label: "Recon", icon: Map, color: "#00d4ff" },
  full: { label: "Full Scan", icon: Shield, color: "#a78bfa" },
  injection: { label: "Injection", icon: Zap, color: "#f97316" },
  static: { label: "Static", icon: Code, color: "#10b981" },
};

const MODE_ORDER: Mode[] = ["recon", "full", "injection", "static"];

/** Pull the headline metrics off a stored scan record (shape varies by mode). */
function scanMetrics(scan: any) {
  const d = scan?.data || {};
  return {
    endpoints: d.surface_report?.total_endpoints || 0,
    headerFindings: d.header_audit_report?.total_findings || 0,
    injectionConfirmed: d.injection_report?.total_confirmed || 0,
    injectionTested: d.injection_report?.total_tested || 0,
    staticVulns: d.static_analysis_report?.triaged_findings?.length || 0,
    staticFalsePositives: d.static_analysis_report?.false_positives?.length || 0,
    staticFixes: d.static_analysis_report?.fixes?.length || 0,
  };
}

/** A single overview stat tile. */
function StatTile({ label, value, accent }: { label: string; value: number | string; accent?: string }) {
  return (
    <div className="bg-card border border-border rounded-xl px-5 py-4">
      <div className="text-2xl font-extrabold text-foreground leading-none" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      <div className="mt-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">{label}</div>
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [scans, setScans] = useState<any[]>([]);
  const [mounted, setMounted] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");

  useEffect(() => {
    setMounted(true);
    if (!isAuthenticated()) {
      router.push("/login");
      return;
    }

    const historyRaw = localStorage.getItem("SecuraAI_scan_history");
    if (historyRaw) {
      setScans(JSON.parse(historyRaw));
    }
  }, [router]);

  const deleteScan = (id: string) => {
    const updatedScans = scans.filter((s) => s.id !== id);
    setScans(updatedScans);
    localStorage.setItem("SecuraAI_scan_history", JSON.stringify(updatedScans));
  };

  if (!mounted) return null;

  // ── Per-mode counts + which modes actually appear in history ──
  const modeCounts = MODE_ORDER.reduce<Record<Mode, number>>((acc, m) => {
    acc[m] = scans.filter((s) => s.mode === m).length;
    return acc;
  }, {} as Record<Mode, number>);
  const presentModes = MODE_ORDER.filter((m) => modeCounts[m] > 0);

  // Keep the active filter valid if its scans were all deleted.
  const effectiveFilter: Filter = filter !== "all" && modeCounts[filter as Mode] === 0 ? "all" : filter;

  const filtered = effectiveFilter === "all" ? scans : scans.filter((s) => s.mode === effectiveFilter);

  // ── Aggregate metrics across the filtered set ──
  const agg = filtered.reduce(
    (a, s) => {
      const m = scanMetrics(s);
      a.endpoints += m.endpoints;
      a.headerFindings += m.headerFindings;
      a.injectionConfirmed += m.injectionConfirmed;
      a.injectionTested += m.injectionTested;
      a.staticVulns += m.staticVulns;
      a.staticFalsePositives += m.staticFalsePositives;
      a.staticFixes += m.staticFixes;
      return a;
    },
    { endpoints: 0, headerFindings: 0, injectionConfirmed: 0, injectionTested: 0, staticVulns: 0, staticFalsePositives: 0, staticFixes: 0 }
  );

  // ── Charts (global, across all scans) ──
  const scansByType = presentModes.map((m) => ({ name: MODE_META[m].label, value: modeCounts[m], color: MODE_META[m].color }));
  const findingsByCategory = (() => {
    const totals = scans.reduce(
      (a, s) => {
        const m = scanMetrics(s);
        a.header += m.headerFindings;
        a.injection += m.injectionConfirmed;
        a.static += m.staticVulns;
        return a;
      },
      { header: 0, injection: 0, static: 0 }
    );
    return [
      { name: "Header", value: totals.header, color: TYPE_COLORS[1] },
      { name: "Injection", value: totals.injection, color: TYPE_COLORS[3] },
      { name: "Static", value: totals.static, color: TYPE_COLORS[2] },
    ].filter((d) => d.value > 0);
  })();

  const tabs: { id: Filter; label: string; count: number }[] = [
    { id: "all", label: "All Scans", count: scans.length },
    ...presentModes.map((m) => ({ id: m as Filter, label: MODE_META[m].label, count: modeCounts[m] })),
  ];

  return (
    <DashboardLayout activeId="dashboard">
      <div className="max-w-6xl mx-auto flex flex-col gap-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-foreground tracking-tight">Dashboard</h1>
            <p className="mt-2 text-sm text-muted-foreground">Overview of your recent security scans.</p>
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
              You haven&apos;t run any security scans yet. Start a new scan to see the results here.
            </p>
            <Link href="/scan" className="bg-white text-black hover:bg-neutral-200 font-medium px-6 py-2.5 rounded-md transition-colors">
              Run New Scan
            </Link>
          </div>
        ) : (
          <>
            {/* ── Filter tabs by scan type ── */}
            <div className="flex flex-wrap gap-2 border-b border-border pb-3">
              {tabs.map((t) => {
                const isActive = effectiveFilter === t.id;
                const Icon = t.id === "all" ? LayoutList : MODE_META[t.id as Mode].icon;
                return (
                  <button
                    key={t.id}
                    onClick={() => setFilter(t.id)}
                    className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-colors border ${
                      isActive
                        ? "bg-primary/15 text-foreground border-primary/40"
                        : "bg-card text-muted-foreground border-border hover:text-foreground hover:border-border/80"
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    {t.label}
                    <span className={`text-[11px] px-1.5 py-0.5 rounded-full ${isActive ? "bg-primary/25 text-foreground" : "bg-secondary text-muted-foreground"}`}>
                      {t.count}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* ── Filter-aware metric tiles ── */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatTile label={effectiveFilter === "all" ? "Total Scans" : `${MODE_META[effectiveFilter as Mode].label} Scans`} value={filtered.length} />
              {(effectiveFilter === "all" || effectiveFilter === "recon" || effectiveFilter === "full" || effectiveFilter === "injection") && (
                <StatTile label={effectiveFilter === "injection" ? "Endpoints Tested" : "Endpoints Mapped"} value={effectiveFilter === "injection" ? agg.injectionTested : agg.endpoints} />
              )}
              {(effectiveFilter === "all" || effectiveFilter === "full") && (
                <StatTile label="Header Findings" value={agg.headerFindings} accent={agg.headerFindings > 0 ? "#f59e0b" : undefined} />
              )}
              {(effectiveFilter === "all" || effectiveFilter === "injection") && (
                <StatTile label="Injection Vulns" value={agg.injectionConfirmed} accent={agg.injectionConfirmed > 0 ? "#ef4444" : undefined} />
              )}
              {(effectiveFilter === "all" || effectiveFilter === "static") && (
                <StatTile label="Static Vulns" value={agg.staticVulns} accent={agg.staticVulns > 0 ? "#ef4444" : undefined} />
              )}
              {effectiveFilter === "static" && (
                <>
                  <StatTile label="False Positives" value={agg.staticFalsePositives} />
                  <StatTile label="Fixes Generated" value={agg.staticFixes} accent={agg.staticFixes > 0 ? "#00d4ff" : undefined} />
                </>
              )}
            </div>

            {/* ── Overview charts ── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="p-4 bg-card border border-border rounded-xl">
                <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                  <Activity size={13} /> Scans by Type
                </div>
                <VerticalBars data={scansByType} emptyLabel="No scans yet" />
              </div>
              <div className="p-4 bg-card border border-border rounded-xl flex flex-col">
                <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                  <Bug size={13} /> Findings by Category
                </div>
                <DonutChart data={findingsByCategory} centerLabel="Findings" emptyLabel="No findings across scans" />
                {findingsByCategory.length > 0 && (
                  <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 justify-center">
                    {findingsByCategory.map((d) => (
                      <span key={d.name} className="flex items-center gap-1 text-[11px] text-muted-foreground">
                        <span className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                        {d.name} ({d.value})
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* ── Scan history list (filtered) ── */}
            <div className="flex flex-col gap-4">
              <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                {effectiveFilter === "all" ? "All Scans" : `${MODE_META[effectiveFilter as Mode].label} Scans`} ({filtered.length})
              </h2>
              <div className="grid gap-4">
                {filtered.map((scan) => {
                  const mode: Mode = MODE_ORDER.includes(scan.mode) ? scan.mode : "recon";
                  const meta = MODE_META[mode];
                  const Icon = meta.icon;
                  const m = scanMetrics(scan);
                  const isStatic = mode === "static";

                  // Headline metric per mode.
                  const headline =
                    mode === "static" ? { value: m.staticVulns, label: "Vulnerabilities" }
                    : mode === "injection" ? { value: m.injectionConfirmed, label: "Confirmed Vulns" }
                    : mode === "full" ? { value: m.headerFindings, label: "Header Findings" }
                    : { value: m.endpoints, label: "Endpoints" };

                  return (
                    <div key={scan.id} className="bg-card border border-border rounded-lg p-5 flex flex-col sm:flex-row gap-4 sm:items-center justify-between hover:border-primary/50 transition-colors">
                      <div className="flex items-start gap-4 min-w-0">
                        <div className="w-10 h-10 rounded-full flex items-center justify-center shrink-0" style={{ background: `${meta.color}1a` }}>
                          <Icon className="h-5 w-5" style={{ color: meta.color }} />
                        </div>
                        <div className="min-w-0">
                          <h3 className="font-semibold text-base flex items-center gap-2 min-w-0">
                            <span className="truncate max-w-[380px]" title={scan.url}>{scan.url}</span>
                            <span
                              className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full shrink-0"
                              style={{ background: `${meta.color}1a`, color: meta.color }}
                            >
                              {meta.label}
                            </span>
                          </h3>
                          <div className="flex flex-wrap items-center gap-4 mt-2 text-sm text-muted-foreground">
                            <span className="flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" /> {new Date(scan.timestamp).toLocaleString()}</span>
                            <span className="flex items-center gap-1.5">
                              {isStatic ? <FolderGit2 className="h-3.5 w-3.5" /> : <Globe className="h-3.5 w-3.5" />}
                              {isStatic ? `${m.staticFixes} fix${m.staticFixes !== 1 ? "es" : ""}` : `${m.endpoints} Endpoints`}
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-6 mt-4 sm:mt-0 pt-4 sm:pt-0 border-t sm:border-t-0 border-border">
                        <div className="text-center sm:text-right">
                          <div className="text-2xl font-bold" style={headline.value > 0 && (mode === "injection" || mode === "static") ? { color: "#ef4444" } : undefined}>
                            {headline.value}
                          </div>
                          <div className="text-xs text-muted-foreground uppercase tracking-wider">{headline.label}</div>
                        </div>

                        <Link
                          href={`/reports?id=${scan.id}`}
                          className="flex items-center gap-2 px-4 py-2 rounded-md bg-secondary hover:bg-secondary/80 text-sm font-medium transition-colors ml-auto sm:ml-0"
                        >
                          View Report <ArrowRight className="h-4 w-4" />
                        </Link>
                        <button
                          onClick={() => deleteScan(scan.id)}
                          className="p-2 text-muted-foreground hover:text-red-500 hover:bg-red-500/10 rounded-md transition-colors"
                          title="Delete Scan"
                        >
                          <Trash2 className="h-5 w-5" />
                        </button>
                      </div>
                    </div>
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
