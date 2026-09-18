"use client";

export const dynamic = "force-dynamic";


import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  Shield, Globe, Clock, Activity, ArrowRight,
  Map, Zap, Code, FolderGit2, Bug, LayoutList, PlusCircle
} from "lucide-react";
import { getScanHistory } from "@/lib/api";
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

  useEffect(() => {
    setMounted(true);
    if (!isAuthenticated()) {
      router.push("/login");
      return;
    }

    getScanHistory().then(setScans).catch(console.error);
  }, [router]);

  if (!mounted) return null;

  // ── Aggregate metrics across ALL scans ──
  const agg = scans.reduce(
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
  // ── Per-mode counts + which modes actually appear in history ──
  const modeCounts = MODE_ORDER.reduce<Record<Mode, number>>((acc, m) => {
    acc[m] = scans.filter((s) => s.mode === m).length;
    return acc;
  }, {} as Record<Mode, number>);
  const presentModes = MODE_ORDER.filter((m) => modeCounts[m] > 0);

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
            {/* ── Metric tiles ── */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatTile label="Total Scans" value={scans.length} />
              <StatTile label="Endpoints Mapped/Tested" value={agg.endpoints + agg.injectionTested} />
              <StatTile label="Header Findings" value={agg.headerFindings} accent={agg.headerFindings > 0 ? "#f59e0b" : undefined} />
              <StatTile label="Injection Vulns" value={agg.injectionConfirmed} accent={agg.injectionConfirmed > 0 ? "#ef4444" : undefined} />
              <StatTile label="Static Vulns" value={agg.staticVulns} accent={agg.staticVulns > 0 ? "#ef4444" : undefined} />
              <StatTile label="False Positives" value={agg.staticFalsePositives} />
              <StatTile label="Fixes Generated" value={agg.staticFixes} accent={agg.staticFixes > 0 ? "#00d4ff" : undefined} />
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

            <div className="mt-6 flex justify-center">
              <Link href="/recent" className="flex items-center gap-2 text-sm font-medium text-primary hover:text-primary/80 transition-colors">
                View all recent scans <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
