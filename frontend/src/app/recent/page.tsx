"use client";

export const dynamic = "force-dynamic";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  Shield, Globe, Clock, ArrowRight,
  Map, Zap, Code, FolderGit2, Loader2, LayoutList
} from "lucide-react";
import { getScanHistory } from "@/lib/api";

type Mode = "recon" | "full" | "injection" | "static";
type Filter = "all" | Mode;

const MODE_META: Record<Mode, { label: string; icon: React.ElementType; color: string }> = {
  recon: { label: "Recon", icon: Map, color: "#00d4ff" },
  full: { label: "Full Scan", icon: Shield, color: "#a78bfa" },
  injection: { label: "Injection", icon: Zap, color: "#f97316" },
  static: { label: "Static", icon: Code, color: "#10b981" },
};

const MODE_ORDER: Mode[] = ["recon", "full", "injection", "static"];

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

export default function RecentScansPage() {
  const router = useRouter();
  const [scans, setScans] = useState<any[]>([]);
  const [mounted, setMounted] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getScanHistory()
      .then((data) => {
        setScans(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load scans:", err);
        setLoading(false);
      });
    setMounted(true);
  }, []);

  if (!mounted) return null;

  // Verify filter still has matching scans, fallback to 'all' if empty
  const hasFilterScans = filter === "all" || scans.some(s => s.mode === filter);
  const effectiveFilter = hasFilterScans ? filter : "all";
  const filtered = effectiveFilter === "all" ? scans : scans.filter(s => s.mode === effectiveFilter);

  const tabs = [
    { id: "all", label: "All Scans", count: scans.length },
    ...MODE_ORDER
      .map(mode => ({ id: mode, label: MODE_META[mode].label, count: scans.filter(s => s.mode === mode).length }))
      .filter(t => t.count > 0)
  ];

  return (
    <DashboardLayout activeId="activity">
      <div className="mx-auto max-w-5xl flex flex-col gap-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground tracking-tight">Recent Scans</h1>
          <p className="text-muted-foreground mt-1">History of all your vulnerability scans.</p>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-20 text-muted-foreground">
            <Loader2 className="w-6 h-6 animate-spin mr-3" /> Loading scan history...
          </div>
        ) : scans.length === 0 ? (
          <div className="border border-dashed border-border rounded-xl p-12 text-center flex flex-col items-center">
            <div className="w-16 h-16 bg-secondary rounded-full flex items-center justify-center mb-4">
              <Globe className="w-8 h-8 text-muted-foreground" />
            </div>
            <h3 className="text-lg font-semibold text-foreground">No Scans Found</h3>
            <p className="text-muted-foreground mt-2 max-w-sm mb-6">
              You haven't run any security scans yet. Head over to the scan page to start mapping your attack surface.
            </p>
            <Link href="/scan/full" className="bg-white text-black hover:bg-neutral-200 font-medium px-6 py-2.5 rounded-md transition-colors">
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
                    onClick={() => setFilter(t.id as Filter)}
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
