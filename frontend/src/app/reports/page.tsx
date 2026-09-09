"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  AlertTriangle, AlertCircle, AlertOctagon, Info, ShieldAlert,
  Key, Zap, FileCode, FormInput, LayoutDashboard, HelpCircle,
  Shield, Map, Lock, Globe, Clock, ChevronDown, ChevronRight, FileText, Check, Code,
  FolderGit2, Wrench, Activity
} from "lucide-react";
import type { FullScanResponse, ReconResponse, Endpoint, HeaderCheckResult, InjectionReport, InjectionFinding, StaticAnalysisReport, MergedFinding, SafePattern, StaticFix, TaintEvidence, ToolRunStatus } from "@/lib/api";
import { DonutChart, CategoryBars, RiskGauge, computeRiskScore, SEVERITY_COLORS, TYPE_COLORS } from "@/components/ui/report-charts";
import styles from "../dashboard/dashboard.module.css";

type ScanData = FullScanResponse | ReconResponse;
type TabId = "surface" | "headers" | "injection" | "static";

function isFullScan(data: ScanData): data is FullScanResponse {
  return "header_audit_report" in data;
}

/** Count items into a {value: count} map by a key accessor. */
function countBy<T>(items: T[], key: (item: T) => string | undefined): Record<string, number> {
  return items.reduce<Record<string, number>>((acc, item) => {
    const k = key(item) || "unknown";
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {});
}

/** Pick the first meaningful tab for a scan record (static scans have no surface). */
function firstTabFor(scan: any): TabId {
  const d = scan?.data || {};
  if (d.surface_report) return "surface";
  if (d.static_analysis_report) return "static";
  if (d.header_audit_report) return "headers";
  if (d.injection_report) return "injection";
  return "surface";
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_ICONS: Record<string, React.ReactNode> = {
  critical: <ShieldAlert size={14} className="text-red-500" />,
  high: <AlertTriangle size={14} className="text-orange-500" />,
  medium: <AlertCircle size={14} className="text-yellow-500" />,
  low: <AlertOctagon size={14} className="text-blue-500" />,
  info: <Info size={14} className="text-purple-500" />,
};

const ENDPOINT_TYPE_ICONS: Record<string, React.ReactNode> = {
  auth_page: <Key size={14} />,
  api: <Zap size={14} />,
  static_asset: <FileCode size={14} />,
  form: <FormInput size={14} />,
  dashboard: <LayoutDashboard size={14} />,
  unknown: <HelpCircle size={14} />,
};

export default function ReportsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [scans, setScans] = useState<any[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  
  const [activeTab, setActiveTab] = useState<TabId>("surface");
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [showDiscarded, setShowDiscarded] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    if (!isAuthenticated()) {
      router.push("/login");
      return;
    }

    const historyRaw = localStorage.getItem("authtrack_scan_history");
    if (historyRaw) {
      const history = JSON.parse(historyRaw);
      setScans(history);
      
      const queryId = searchParams.get("id");
      if (queryId && history.find((s: any) => s.id === queryId)) {
        setActiveScanId(queryId);
        setActiveTab(firstTabFor(history.find((s: any) => s.id === queryId)));
      } else if (history.length > 0) {
        setActiveScanId(history[0].id);
        setActiveTab(firstTabFor(history[0]));
      }
    }
  }, [router, searchParams]);

  if (!mounted) return null;

  if (scans.length === 0) {
    return (
      <DashboardLayout activeId="reports">
        <div className={styles.noData}>
          <div className={styles.noDataCard}>
            <div className={styles.noDataIcon}><FileText size={48} className="text-purple-400 mx-auto" /></div>
            <h1 className={styles.noDataTitle}>No Reports Available</h1>
            <p className={styles.noDataDesc}>
              Run a scan to generate detailed security reports.
            </p>
            <Link href="/scan" className={styles.noDataBtn}>
              🚀 Go to Scanner
            </Link>
          </div>
        </div>
      </DashboardLayout>
    );
  }

  const activeScan = scans.find(s => s.id === activeScanId) || scans[0];
  const scanData = activeScan.data;
  const scanMode = activeScan.mode;
  const scanUrl = activeScan.url;

  const surfaceReport = scanData.surface_report;
  const auditReport = isFullScan(scanData) ? scanData.header_audit_report : null;
  const scanErrors = scanData.errors || [];

  const injectionReport: InjectionReport | null = scanData.injection_report || null;
  const injectionFindings: InjectionFinding[] = injectionReport?.findings || [];

  const staticReport: StaticAnalysisReport | null = scanData.static_analysis_report || null;
  const staticFindings: MergedFinding[] = staticReport?.confirmed_findings || [];
  const safePatterns: SafePattern[] = staticReport?.safe_patterns || [];
  const staticFixes: StaticFix[] = staticReport?.fixes || [];

  const endpoints: Endpoint[] = surfaceReport?.endpoints || [];
  // The fail/missing subset (LLM-scored) drives the severity filter + risk gauge.
  const findings: HeaderCheckResult[] = auditReport?.findings || [];
  // The full checklist (pass + fail + missing) drives the both-sides view.
  const checklist: HeaderCheckResult[] = auditReport?.checklist || [];
  const filteredFindings =
    filterSeverity === "all"
      ? findings
      : findings.filter((f) => f.severity === filterSeverity);

  // Group the full checklist by endpoint so each URL renders its own
  // green/red/amber panel — the securityheaders.com / Observatory pattern.
  const checklistByEndpoint: [string, HeaderCheckResult[]][] = Object.entries(
    checklist.reduce<Record<string, HeaderCheckResult[]>>((acc, item) => {
      (acc[item.url] ||= []).push(item);
      return acc;
    }, {})
  );
  const configuredCount = auditReport?.configured_count ?? 0;
  const gradedTotal = auditReport?.graded_total ?? 0;
  const configuredPct = gradedTotal > 0 ? Math.round((configuredCount / gradedTotal) * 100) : 0;

  // Severity counts (fail/missing findings only).
  const severityCounts = SEVERITY_ORDER.reduce<Record<string, number>>(
    (acc, sev) => {
      acc[sev] = findings.filter((f) => f.severity === sev).length;
      return acc;
    },
    {}
  );

  // Endpoint type counts
  const typeCounts = endpoints.reduce<Record<string, number>>((acc, ep) => {
    const t = ep.endpoint_type || "unknown";
    acc[t] = (acc[t] || 0) + 1;
    return acc;
  }, {});

  // ── Which tabs are available for this scan (static scans have no surface) ──
  const availableTabs: { id: TabId; label: string; icon: React.ReactNode; count: number; alert: boolean }[] = [];
  if (surfaceReport) availableTabs.push({ id: "surface", label: "Attack Surface", icon: <Map size={16} className="mr-2 inline" />, count: surfaceReport?.total_endpoints ?? 0, alert: false });
  if (auditReport) availableTabs.push({ id: "headers", label: "Header Audit", icon: <Lock size={16} className="mr-2 inline" />, count: auditReport.total_findings, alert: auditReport.total_findings > 0 });
  if (injectionReport) availableTabs.push({ id: "injection", label: "Injection Test", icon: <Zap size={16} className="mr-2 inline" />, count: injectionReport.total_confirmed, alert: injectionReport.total_confirmed > 0 });
  if (staticReport) availableTabs.push({ id: "static", label: "Static Analysis", icon: <Code size={16} className="mr-2 inline" />, count: staticFindings.length, alert: staticFindings.length > 0 });

  // ── Unified severity distribution driving the risk gauge + donut ──
  // Each scan has one primary finding source, so only one branch applies.
  let riskCounts: Record<string, number> = {};
  if (auditReport) {
    riskCounts = severityCounts;
  } else if (injectionReport) {
    riskCounts = (injectionReport.severity_breakdown && Object.keys(injectionReport.severity_breakdown).length > 0)
      ? injectionReport.severity_breakdown
      : countBy(injectionFindings, (f) => (f.severity || "").toLowerCase());
  } else if (staticReport) {
    riskCounts = countBy(staticFindings, (f) => (f.final_severity || f.severity || "").toLowerCase());
  }
  const riskScore = computeRiskScore(riskCounts);

  const severityDonutData = SEVERITY_ORDER
    .map((sev) => ({ name: sev, value: riskCounts[sev] || 0 }))
    .filter((d) => d.value > 0);

  // Category bar data + label vary by scan focus.
  let categoryBarData: { name: string; value: number; color?: string }[] = [];
  let categoryBarLabel = "";
  if (injectionReport && Object.keys(injectionReport.type_breakdown || {}).length > 0) {
    categoryBarData = Object.entries(injectionReport.type_breakdown).map(([k, v], i) => ({
      name: k.replace(/_/g, " "), value: v as number, color: TYPE_COLORS[i % TYPE_COLORS.length],
    }));
    categoryBarLabel = "Vulnerabilities by Injection Type";
  } else if (staticReport) {
    const byFile = countBy(staticFindings, (f) => (f.file || "").split(/[\\/]/).pop());
    categoryBarData = Object.entries(byFile).map(([k, v], i) => ({
      name: k, value: v as number, color: TYPE_COLORS[i % TYPE_COLORS.length],
    }));
    categoryBarLabel = "Findings by File";
  } else {
    categoryBarData = Object.entries(typeCounts).map(([k, v], i) => ({
      name: k.replace(/_/g, " "), value: v as number, color: TYPE_COLORS[i % TYPE_COLORS.length],
    }));
    categoryBarLabel = "Endpoints by Type";
  }

  // Recon-only scans have no severity data — show the endpoint donut instead of a gauge.
  const hasRiskData = !!auditReport || !!injectionReport || !!staticReport;
  const endpointDonutData = Object.entries(typeCounts).map(([k, v]) => ({ name: k.replace(/_/g, " "), value: v as number }));

  const scanTs = activeScan.timestamp
    ? new Date(activeScan.timestamp).toLocaleString()
    : "—";

  return (
    <DashboardLayout activeId="reports">
      <div className={styles.main}>
        {/* Scan Selector */}
        <div className="mb-6 flex flex-col sm:flex-row gap-4 items-center justify-between p-4 bg-card border border-border rounded-xl">
          <div className="text-sm font-medium text-muted-foreground flex items-center gap-2">
            <FileText size={16} /> Detailed Scan Report
          </div>
          <select 
            className="bg-background border border-border rounded-md px-3 py-1.5 text-sm w-full sm:w-auto min-w-[300px]"
            value={activeScan.id}
            onChange={(e) => {
              const nextScan = scans.find((s) => s.id === e.target.value);
              setActiveScanId(e.target.value);
              setActiveTab(firstTabFor(nextScan));
              setExpandedFinding(null);
              setFilterSeverity("all");
              // Update URL without reloading
              router.replace(`/reports?id=${e.target.value}`, { scroll: false });
            }}
          >
            {scans.map(s => (
              <option key={s.id} value={s.id}>
                {new Date(s.timestamp).toLocaleString()} — {s.url}
              </option>
            ))}
          </select>
        </div>

        {/* ── Dashboard Header ── */}
        <div className={styles.dashHeader}>
          <div className={styles.dashHeaderLeft}>
            <div className={styles.dashBadge}>
              {scanMode === "full" ? "Full Scan" : scanMode === "injection" ? "Injection Test" : scanMode === "static" ? "Static Analysis" : "Recon Only"}
            </div>
            <h1 className={styles.dashTitle}>Report Overview</h1>
            <div className={styles.dashMeta}>
              <span className={styles.dashMetaItem}>
                <span className={styles.dashMetaIcon}>{scanMode === "static" ? <FolderGit2 size={14} /> : <Globe size={14} />}</span>
                <code className={styles.dashUrl}>{scanUrl}</code>
              </span>
              <span className={styles.dashMetaDivider}>·</span>
              <span className={styles.dashMetaItem}>
                <span className={styles.dashMetaIcon}><Clock size={14} /></span>
                {scanTs}
              </span>
            </div>
          </div>
        </div>

        {/* ── Summary Stats (mode-aware) ── */}
        <div className={styles.statsRow}>
          {surfaceReport && (
            <div className={styles.statCard}>
              <div className={styles.statValue}>{surfaceReport?.total_endpoints ?? 0}</div>
              <div className={styles.statLabel}>Endpoints Found</div>
            </div>
          )}
          {auditReport && (
            <>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{auditReport.total_findings}</div>
                <div className={styles.statLabel}>Header Findings</div>
              </div>
              {SEVERITY_ORDER.map((sev) =>
                severityCounts[sev] > 0 ? (
                  <div
                    key={sev}
                    className={`${styles.statCard} ${styles[`statCard_${sev}`]}`}
                  >
                    <div className={`${styles.statValue} ${styles[`statValue_${sev}`]}`}>
                      {severityCounts[sev]}
                    </div>
                    <div className={styles.statLabel}>
                      {SEVERITY_ICONS[sev]} {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </div>
                  </div>
                ) : null
              )}
            </>
          )}
          {injectionReport && (
            <>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{injectionReport.total_tested}</div>
                <div className={styles.statLabel}>Endpoints Tested</div>
              </div>
              <div className={`${styles.statCard} ${styles.statCard_critical}`}>
                <div className={styles.statValue} style={{ WebkitTextFillColor: "#ef4444" }}>{injectionReport.total_confirmed}</div>
                <div className={styles.statLabel}>Confirmed Vulns</div>
              </div>
            </>
          )}
          {staticReport && (
            <>
              <div className={`${styles.statCard} ${styles.statCard_critical}`}>
                <div className={styles.statValue} style={{ WebkitTextFillColor: "#ef4444" }}>{staticFindings.length}</div>
                <div className={styles.statLabel}>Vulnerabilities</div>
              </div>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{staticReport.ruled_out_findings?.length || 0}</div>
                <div className={styles.statLabel}>False Positives</div>
              </div>
              <div className={styles.statCard}>
                <div className={styles.statValue} style={{ WebkitTextFillColor: "#22c55e" }}>{safePatterns.length}</div>
                <div className={styles.statLabel}>Security Controls</div>
              </div>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{staticFixes.length}</div>
                <div className={styles.statLabel}>Fixes Generated</div>
              </div>
            </>
          )}
        </div>

        {/* ── Visual Overview (Recharts) ── */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
          {/* Risk gauge (severity-bearing scans) or endpoint donut (recon-only) */}
          <div className="p-4 bg-card border border-border rounded-xl flex flex-col">
            <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              {hasRiskData
                ? <><Activity size={13} /> Risk Score</>
                : <><Map size={13} /> Endpoint Distribution</>}
            </div>
            {hasRiskData ? (
              <RiskGauge score={riskScore} />
            ) : (
              <DonutChart data={endpointDonutData} centerLabel="Endpoints" emptyLabel="No endpoints" />
            )}
          </div>

          {/* Severity donut */}
          <div className="p-4 bg-card border border-border rounded-xl flex flex-col">
            <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <ShieldAlert size={13} /> Severity Breakdown
            </div>
            <DonutChart
              data={severityDonutData}
              centerLabel="Findings"
              useSeverityColors
              emptyLabel="No findings — clean result"
            />
            {severityDonutData.length > 0 && (
              <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2 justify-center">
                {severityDonutData.map((d) => (
                  <span key={d.name} className="flex items-center gap-1 text-[11px] text-muted-foreground capitalize">
                    <span className="w-2 h-2 rounded-full" style={{ background: SEVERITY_COLORS[d.name] }} />
                    {d.name} ({d.value})
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Category bars */}
          <div className="p-4 bg-card border border-border rounded-xl flex flex-col">
            <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <FileText size={13} /> {categoryBarLabel}
            </div>
            <CategoryBars data={categoryBarData} emptyLabel="No data" />
          </div>
        </div>

        {/* ── LLM Executive Summary ── */}
        {(auditReport?.summary || injectionReport?.summary) && (
          <div className={styles.summaryCard}>
            <div className={styles.summaryCardHeader}>
              <span className={styles.summaryIcon}>🤖</span>
              <span className={styles.summaryTitle}>AI Executive Summary</span>
            </div>
            <p className={styles.summaryText}>{auditReport?.summary || injectionReport?.summary}</p>
          </div>
        )}

        {/* ── Errors/Warnings ── */}
        {scanErrors.length > 0 && (
          <details className={styles.warningCard}>
            <summary className={styles.warningSummary}>
              ⚠️ {scanErrors.length} Warning{scanErrors.length > 1 ? "s" : ""}
            </summary>
            <ul className={styles.warningList}>
              {scanErrors.map((err: string, i: number) => (
                <li key={i} className={styles.warningItem}>{err}</li>
              ))}
            </ul>
          </details>
        )}

        {/* ── Tabs ── */}
        {availableTabs.length > 1 && (
          <div className={styles.tabs}>
            {availableTabs.map((t) => (
              <button
                key={t.id}
                className={`${styles.tab} ${activeTab === t.id ? styles.tabActive : ""}`}
                onClick={() => { setActiveTab(t.id); setExpandedFinding(null); }}
              >
                {t.icon} {t.label}
                <span className={`${styles.tabCount} ${t.alert ? styles.tabCountAlert : ""}`}>
                  {t.count}
                </span>
              </button>
            ))}
          </div>
        )}

        {/* ── Surface Report Tab ── */}
        {activeTab === "surface" && surfaceReport && (
          <section className={styles.section}>
            <h2 className={styles.sectionTitle}><Map size={20} className="mr-2 inline" /> Attack Surface Map</h2>

            {/* Type breakdown */}
            <div className={styles.typeBreakdown}>
              {Object.entries(typeCounts).map(([type, count]) => (
                <div key={type} className={styles.typeCard}>
                  <span className={styles.typeIcon}>{ENDPOINT_TYPE_ICONS[type] || <HelpCircle size={14} />}</span>
                  <span className={styles.typeCount}>{count as number}</span>
                  <span className={styles.typeName}>{type.replace(/_/g, " ")}</span>
                </div>
              ))}
            </div>

            {/* Endpoints table */}
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Status</th>
                    <th>Tech / Size</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((ep: any, i: number) => (
                    <tr key={i} className={styles.tableRow}>
                      <td>
                        <span className={`${styles.epTypeBadge} ${styles[`epType_${ep.endpoint_type}`]} flex items-center gap-1.5`}>
                          {ENDPOINT_TYPE_ICONS[ep.endpoint_type] || <HelpCircle size={14} />}
                          {ep.endpoint_type?.replace(/_/g, " ") || "unknown"}
                        </span>
                        {ep.classification_reason && (
                          <div className="text-[9px] text-muted-foreground/60 mt-1 italic leading-tight">{ep.classification_reason}</div>
                        )}
                      </td>
                      <td className={styles.urlCell} title={ep.url}>
                        <div className="flex flex-col gap-1">
                          <a href={ep.url} target="_blank" rel="noopener noreferrer" className={styles.urlLink}>
                            {ep.url.length > 50 ? ep.url.slice(0, 50) + "…" : ep.url}
                          </a>
                          {/* Show actual evidence flags instead of bare "Flagged" boolean */}
                          {ep.flags && ep.flags.length > 0 && (
                            <div className="flex flex-col gap-0.5">
                              {ep.flags.map((flag: string, fi: number) => (
                                <span key={fi} className="bg-yellow-500/10 text-yellow-500 text-[9px] px-1.5 py-0.5 rounded border border-yellow-500/20 font-mono leading-tight">
                                  {flag}
                                </span>
                              ))}
                            </div>
                          )}
                          {ep.detection_source && (
                            <span className="text-[9px] text-muted-foreground/50 font-mono">↳ Source: {ep.detection_source}</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className={`${styles.methodBadge} ${styles[`method_${ep.method?.toLowerCase()}`]}`}>
                          {ep.method}
                        </span>
                        {ep.content_type && ep.content_type !== "form" && (
                          <div className="text-[9px] text-muted-foreground/50 mt-0.5 font-mono">{ep.content_type.split(';')[0]}</div>
                        )}
                      </td>
                      <td>
                        <span className={`${styles.statusBadge} ${ep.status_code >= 400 ? styles.statusError : ep.status_code >= 300 ? styles.statusWarn : styles.statusOk}`}>
                          {ep.status_code || "—"}
                        </span>
                      </td>
                      <td className="text-xs text-muted-foreground">
                        {ep.response_size ? <div className="mb-1">{Math.round(ep.response_size / 1024)} KB <span className="text-muted-foreground/50">({ep.response_time}s)</span></div> : null}
                        {ep.technology && ep.technology.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {ep.technology.map((t: string, i: number) => (
                              <span key={i} className="px-1.5 py-0.5 bg-secondary text-[10px] rounded border border-border/50">{t}</span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="text-xs max-w-[200px]">
                        {ep.parameters && ep.parameters.length > 0 && (
                          <div className="flex flex-wrap gap-1 mb-1">
                            {ep.parameters.map((p: string, i: number) => (
                              <span key={i} className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 rounded border border-blue-500/20 text-[10px]">{p}=?</span>
                            ))}
                          </div>
                        )}
                        {ep.form_inputs && ep.form_inputs.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            <span className="text-muted-foreground text-[10px] flex items-center"><FormInput size={10} className="mr-1" />Form:</span>
                            {ep.form_inputs.map((inp: string, i: number) => (
                              <span key={i} className="px-1.5 py-0.5 bg-orange-500/10 text-orange-400 rounded border border-orange-500/20 text-[10px]">{inp}</span>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* ── Header Audit Tab ── */}
        {auditReport && activeTab === "headers" && (
          <section className={styles.section}>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}><Lock size={20} className="mr-2 inline" /> Security Header Audit</h2>

              {/* Severity filter (applies to the fail/missing findings list) */}
              <div className={styles.filterRow}>
                {["all", ...SEVERITY_ORDER].map((sev) => (
                  <button
                    key={sev}
                    className={`${styles.filterPill} ${filterSeverity === sev ? styles.filterPillActive : ""} ${sev !== "all" ? styles[`filterPill_${sev}`] : ""}`}
                    onClick={() => setFilterSeverity(sev)}
                  >
                    {sev === "all" ? "All" : `${SEVERITY_ICONS[sev]} ${sev}`}
                    {sev !== "all" && severityCounts[sev] > 0 && (
                      <span className={styles.filterCount}>{severityCounts[sev]}</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* ── Configured ratio banner (the "8/10 configured" headline) ── */}
            {gradedTotal > 0 && (
              <div className="mb-6 p-5 bg-card border border-border rounded-xl">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <div className="text-2xl font-bold text-foreground">
                      {configuredCount}<span className="text-muted-foreground text-lg">/{gradedTotal}</span>{" "}
                      <span className="text-base font-medium text-muted-foreground">security controls configured</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      Across {auditReport.endpoints_audited} endpoint(s) · {findings.length} need attention
                    </div>
                  </div>
                  <div className={`text-3xl font-bold ${configuredPct >= 80 ? "text-green-400" : configuredPct >= 50 ? "text-amber-400" : "text-red-400"}`}>
                    {configuredPct}%
                  </div>
                </div>
                <div className="h-2.5 w-full bg-secondary rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${configuredPct >= 80 ? "bg-green-500" : configuredPct >= 50 ? "bg-amber-500" : "bg-red-500"}`}
                    style={{ width: `${configuredPct}%` }}
                  />
                </div>
              </div>
            )}

            {/* ── Per-endpoint checklist (both sides: pass / fail / missing) ── */}
            {checklistByEndpoint.length > 0 && (
              <div className="mb-6 space-y-4">
                {checklistByEndpoint.map(([url, items], ei) => {
                  const passCount = items.filter((it) => it.status === "pass").length;
                  return (
                    <div key={ei} className="bg-card border border-border rounded-xl overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-border flex items-center gap-2 bg-secondary/30">
                        <Globe size={13} className="text-muted-foreground shrink-0" />
                        <code className="text-[11px] text-foreground/80 truncate" title={url}>{url}</code>
                        <span className="ml-auto text-[10px] text-muted-foreground shrink-0">
                          {passCount}/{items.filter((it) => it.weight ?? 0 > 0 ? true : it.status === "pass").length || items.length} ok
                        </span>
                      </div>
                      <div className="divide-y divide-border/50">
                        {items.map((it, ii) => {
                          const isPass = it.status === "pass";
                          const isMissing = it.status === "missing";
                          return (
                            <div key={ii} className="flex items-start gap-3 px-4 py-2.5 text-xs">
                              <span className="shrink-0 mt-0.5">
                                {isPass ? (
                                  <Check size={14} className="text-green-400" />
                                ) : isMissing ? (
                                  <AlertOctagon size={14} className="text-red-400" />
                                ) : (
                                  <AlertCircle size={14} className="text-amber-400" />
                                )}
                              </span>
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <code className="text-[11px] font-medium text-foreground">{it.header_name}</code>
                                  <span className={`px-1.5 py-0.5 text-[9px] font-medium uppercase rounded border ${
                                    isPass
                                      ? "bg-green-500/10 text-green-400 border-green-500/20"
                                      : isMissing
                                      ? "bg-red-500/10 text-red-400 border-red-500/20"
                                      : "bg-amber-500/10 text-amber-400 border-amber-500/20"
                                  }`}>
                                    {it.status}
                                  </span>
                                  {!isPass && it.severity && (
                                    <span className={`${styles.severityBadge} ${styles[`severity_${it.severity}`]}`} style={{ fontSize: 9 }}>
                                      {SEVERITY_ICONS[it.severity]} {it.severity}
                                    </span>
                                  )}
                                </div>
                                {it.actual && (
                                  <code className={`block mt-1 text-[10px] break-all ${isPass ? "text-foreground/60" : isMissing ? "text-red-400/70" : "text-amber-400/70"}`}>
                                    {it.actual}
                                  </code>
                                )}
                                {!isPass && it.description && (
                                  <p className="mt-1 text-[10px] text-muted-foreground">{it.description}</p>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            <h3 className="text-sm font-semibold mb-3 mt-8 flex items-center gap-2 text-foreground">
              <AlertTriangle size={14} className="text-amber-400" /> Findings requiring attention
            </h3>

            {filteredFindings.length === 0 ? (
              <div className={styles.noFindings}>
                <Check className="h-5 w-5 text-green-500 mr-2 inline" /> No findings for the selected severity level
              </div>
            ) : (
              <div className={styles.findingsList}>
                {filteredFindings.map((finding: any, i: number) => (
                  <div
                    key={i}
                    className={`${styles.findingCard} ${styles[`finding_${finding.severity}`]}`}
                  >
                    <button
                      className={styles.findingCardHeader}
                      onClick={() =>
                        setExpandedFinding(expandedFinding === i ? null : i)
                      }
                    >
                      <div className={styles.findingLeft}>
                        <span
                          className={`${styles.severityBadge} ${styles[`severity_${finding.severity}`]}`}
                        >
                          {SEVERITY_ICONS[finding.severity]}{" "}
                          {finding.severity.toUpperCase()}
                        </span>
                        <code className={styles.headerName}>{finding.header_name}</code>
                        {/* Status badge: missing (red) vs fail/misconfigured (amber) */}
                        <span className={`px-1.5 py-0.5 text-[9px] font-medium uppercase rounded border ${
                          finding.status === 'missing'
                            ? 'bg-red-500/10 text-red-400 border-red-500/20'
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        }`}>
                          {finding.status}
                        </span>
                      </div>
                      <span className={styles.expandIcon}>
                        {expandedFinding === i ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      </span>
                    </button>

                    {expandedFinding === i && (
                      <div className={styles.findingBody}>
                        <p className={styles.findingDesc}>{finding.description}</p>
                        <div className={styles.findingMeta}>
                          <div className={styles.findingMetaItem}>
                            <span className={styles.findingMetaLabel}>URL</span>
                            <a
                              href={finding.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className={styles.findingMetaValue}
                            >
                              {finding.url}
                            </a>
                          </div>
                          <div className={styles.findingMetaItem}>
                            <span className={styles.findingMetaLabel}>Expected Value</span>
                            <code className={styles.findingMetaCode}>{finding.expected}</code>
                          </div>
                          <div className={styles.findingMetaItem}>
                            <span className={styles.findingMetaLabel}>Actual Value</span>
                            <code
                              className={`${styles.findingMetaCode} ${
                                finding.status === "missing" || !finding.actual
                                  ? styles.findingMissing
                                  : "text-amber-400"
                              }`}
                            >
                              {finding.actual || "—"}
                            </code>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {/* ── Injection Tab ── */}
        {injectionReport && activeTab === "injection" && (
          <section className={styles.section}>
            <h2 className={styles.sectionTitle}><Zap size={20} className="mr-2 inline" /> Injection Test Results</h2>

            {/* Summary cards */}
            <div className={styles.statsRow + " mb-6"}>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{injectionReport.total_tested}</div>
                <div className={styles.statLabel}>Endpoints Tested</div>
              </div>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{injectionReport.total_params_tested || (injectionReport.total_confirmed + injectionReport.total_discarded)}</div>
                <div className={styles.statLabel}>Payloads Tested</div>
              </div>
              <div className={`${styles.statCard} ${styles.statCard_critical}`}>
                <div className={`${styles.statValue}`} style={{ WebkitTextFillColor: '#ef4444' }}>{injectionReport.total_confirmed}</div>
                <div className={styles.statLabel}>Confirmed Vulnerabilities</div>
              </div>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{injectionReport.total_discarded}</div>
                <div className={styles.statLabel}>Discarded (False Positives)</div>
              </div>
            </div>

            {/* Type breakdown */}
            {Object.keys(injectionReport.type_breakdown || {}).length > 0 && (
              <div className={styles.typeBreakdown + " mb-6"}>
                {Object.entries(injectionReport.type_breakdown).map(([type, count]) => (
                  <div key={type} className={styles.typeCard}>
                    <span className={styles.typeIcon}><Zap size={14} /></span>
                    <span className={styles.typeCount}>{count as number}</span>
                    <span className={styles.typeName}>{type.replace(/_/g, ' ').toUpperCase()}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Tested Endpoints Coverage */}
            {injectionReport.tested_endpoints_detail && injectionReport.tested_endpoints_detail.length > 0 && (
              <div className="mb-6 p-4 bg-card border border-border rounded-xl">
                <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                  <Shield size={14} /> Test Coverage
                </h3>
                <div className="grid gap-2">
                  {injectionReport.tested_endpoints_detail.map((ep: any, i: number) => (
                    <div key={i} className="flex items-center gap-3 text-xs py-1.5 px-3 rounded-lg bg-secondary/50">
                      <code className="text-[11px] text-foreground/80 truncate max-w-[300px]" title={ep.url}>
                        {ep.url.length > 50 ? ep.url.slice(0, 50) + '…' : ep.url}
                      </code>
                      <span className="text-muted-foreground">→</span>
                      <span className="text-muted-foreground">{ep.param_count} param(s)</span>
                      <div className="flex gap-1 ml-auto">
                        {ep.injection_types_tested?.map((t: string) => (
                          <span key={t} className="px-1.5 py-0.5 text-[9px] rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 uppercase">
                            {t.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Findings list */}
            {injectionFindings.length === 0 ? (
              <div className={styles.noFindings}>
                <Check className="h-5 w-5 text-green-500 mr-2 inline" /> No injection vulnerabilities confirmed. Tested endpoints appear resilient.
              </div>
            ) : (
              <div className={styles.findingsList}>
                {injectionFindings.map((finding: any, i: number) => (
                  <div
                    key={i}
                    className={`${styles.findingCard} ${styles[`finding_${finding.severity}`]}`}
                  >
                    <button
                      className={styles.findingCardHeader}
                      onClick={() =>
                        setExpandedFinding(expandedFinding === i ? null : i)
                      }
                    >
                      <div className={styles.findingLeft}>
                        <span
                          className={`${styles.severityBadge} ${styles[`severity_${finding.severity}`]}`}
                        >
                          {SEVERITY_ICONS[finding.severity]}{" "}
                          {finding.severity.toUpperCase()}
                        </span>
                        <span className="px-2 py-0.5 text-[10px] rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-medium uppercase">
                          {finding.injection_type.replace(/_/g, ' ')}
                        </span>
                        <code className={styles.headerName}>{finding.parameter}</code>
                        {/* Timing badge for blind injection */}
                        {Math.abs(finding.time_diff || 0) > 1.5 && (
                          <span className="px-2 py-0.5 text-[10px] rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 font-medium flex items-center gap-1">
                            <Clock size={10} /> +{Math.abs(finding.time_diff).toFixed(1)}s
                          </span>
                        )}
                      </div>
                      <span className={styles.expandIcon}>
                        {expandedFinding === i ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      </span>
                    </button>

                    {expandedFinding === i && (
                      <div className={styles.findingBody}>
                        <p className={styles.findingDesc}>{finding.description}</p>
                        <div className={styles.findingMeta}>
                          <div className={styles.findingMetaItem}>
                            <span className={styles.findingMetaLabel}>URL</span>
                            <a
                              href={finding.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className={styles.findingMetaValue}
                            >
                              {finding.url}
                            </a>
                          </div>
                          <div className={styles.findingMetaItem}>
                            <span className={styles.findingMetaLabel}>Parameter</span>
                            <code className={styles.findingMetaCode}>{finding.parameter}</code>
                          </div>
                          <div className={styles.findingMetaItem}>
                            <span className={styles.findingMetaLabel}>Payload Used</span>
                            <code className={styles.findingMetaCode}>{finding.payload_value || finding.payload_name}</code>
                          </div>
                          {finding.time_diff !== undefined && finding.time_diff !== 0 && (
                            <div className={styles.findingMetaItem}>
                              <span className={styles.findingMetaLabel}>Response Time Delta</span>
                              <code className={styles.findingMetaCode}>{finding.time_diff > 0 ? '+' : ''}{finding.time_diff.toFixed(3)}s</code>
                            </div>
                          )}
                        </div>

                        {/* Evidence */}
                        {finding.evidence && (
                          <div className="mt-3 p-3 rounded-lg border" style={{ background: 'rgba(239,68,68,0.05)', borderColor: 'rgba(239,68,68,0.2)' }}>
                            <div className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'rgba(239,68,68,0.7)' }}>Evidence</div>
                            <p className="text-xs leading-relaxed" style={{ color: 'rgba(255,255,255,0.7)' }}>{finding.evidence}</p>
                          </div>
                        )}

                        {/* Baseline vs Payload side-by-side */}
                        {(finding.baseline_snippet || finding.payload_snippet) && (
                          <div className="mt-3 grid grid-cols-2 gap-3">
                            <div className="p-3 rounded-lg border" style={{ background: 'rgba(59,130,246,0.05)', borderColor: 'rgba(59,130,246,0.2)' }}>
                              <div className="text-[10px] font-semibold uppercase tracking-wider mb-2 flex items-center justify-between" style={{ color: 'rgba(59,130,246,0.7)' }}>
                                <span>Baseline Response</span>
                                {finding.baseline_status && <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10">{finding.baseline_status}</span>}
                              </div>
                              <pre className="text-[10px] leading-relaxed whitespace-pre-wrap break-all max-h-[150px] overflow-y-auto" style={{ color: 'rgba(255,255,255,0.5)' }}>
                                {finding.baseline_snippet || '(empty)'}
                              </pre>
                            </div>
                            <div className="p-3 rounded-lg border" style={{ background: 'rgba(239,68,68,0.05)', borderColor: 'rgba(239,68,68,0.2)' }}>
                              <div className="text-[10px] font-semibold uppercase tracking-wider mb-2 flex items-center justify-between" style={{ color: 'rgba(239,68,68,0.7)' }}>
                                <span>Payload Response</span>
                                {finding.payload_status && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10">{finding.payload_status}</span>}
                              </div>
                              <pre className="text-[10px] leading-relaxed whitespace-pre-wrap break-all max-h-[150px] overflow-y-auto" style={{ color: 'rgba(255,255,255,0.5)' }}>
                                {finding.payload_snippet || '(empty)'}
                              </pre>
                            </div>
                          </div>
                        )}

                        {/* Recommendation */}
                        {finding.recommendation && (
                          <div className="mt-3 p-3 rounded-lg border" style={{ background: 'rgba(34,197,94,0.05)', borderColor: 'rgba(34,197,94,0.2)' }}>
                            <div className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'rgba(34,197,94,0.7)' }}>Recommendation</div>
                            <p className="text-xs leading-relaxed" style={{ color: 'rgba(255,255,255,0.7)' }}>{finding.recommendation}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Discarded Findings */}
            {injectionReport.discarded_findings && injectionReport.discarded_findings.length > 0 && (
              <div className="mt-8">
                <button
                  onClick={() => setShowDiscarded(!showDiscarded)}
                  className="flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors mb-4"
                >
                  {showDiscarded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  View {injectionReport.discarded_findings.length} Discarded Attacks (False Positives)
                </button>
                
                {showDiscarded && (
                  <div className={styles.tableWrapper}>
                    <table className={styles.table}>
                      <thead>
                        <tr>
                          <th>Type</th>
                          <th>Parameter</th>
                          <th>Payload</th>
                          <th>Reason Discarded</th>
                        </tr>
                      </thead>
                      <tbody>
                        {injectionReport.discarded_findings.map((df: any, i: number) => (
                          <tr key={i} className={styles.tableRow}>
                            <td>
                              <span className="px-2 py-0.5 text-[10px] rounded bg-secondary text-muted-foreground border border-border uppercase">
                                {df.injection_type?.replace(/_/g, ' ') || 'unknown'}
                              </span>
                            </td>
                            <td><code className="text-xs bg-muted px-1.5 py-0.5 rounded">{df.parameter}</code></td>
                            <td><code className="text-[10px] text-muted-foreground truncate max-w-[200px] block" title={df.payload_value}>{df.payload_value || df.payload_name}</code></td>
                            <td className="text-xs text-muted-foreground">{df.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </section>
        )}
        {/* ── Static Analysis Tab ── */}
        {staticReport && activeTab === "static" && (
          <section className={styles.section}>
            <h2 className={styles.sectionTitle}><Code size={20} className="mr-2 inline" /> Static Analysis Results</h2>

            {/* Scanned target — repo URL for a cloned scan, else the local path */}
            {staticReport.target_path && (
              <div className="mb-6 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                {staticReport.source_repo ? (
                  <><FolderGit2 size={14} className="text-primary" /> Scanned repo{" "}
                    <a href={staticReport.source_repo} target="_blank" rel="noopener noreferrer"
                      className="font-mono text-foreground/80 hover:text-primary underline underline-offset-2">
                      {staticReport.source_repo}
                    </a></>
                ) : (
                  <><FolderGit2 size={14} /> <code className="font-mono text-foreground/80">{staticReport.target_path}</code></>
                )}
                {staticReport.codeql_language && (
                  <span className="ml-2 px-1.5 py-0.5 rounded bg-secondary text-[10px] uppercase tracking-wider">
                    {staticReport.codeql_language}
                  </span>
                )}
              </div>
            )}

            {/* Findings */}
            <div className="mb-8">
              <h3 className="text-sm font-semibold mb-4 text-red-400 border-b border-red-500/20 pb-2">Confirmed Vulnerabilities</h3>
              {staticFindings.length === 0 ? (
                <div className={styles.noFindings}>
                  <Check className="h-5 w-5 text-green-500 mr-2 inline" /> No static vulnerabilities confirmed.
                </div>
              ) : (
                <div className={styles.findingsList}>
                  {staticFindings.map((finding, i) => (
                    <div key={i} className={`${styles.findingCard} ${styles[`finding_${finding.final_severity || finding.severity}`]}`}>
                      <div className={styles.findingCardHeader} style={{ cursor: 'default' }}>
                        <div className={styles.findingLeft}>
                          <span className={`${styles.severityBadge} ${styles[`severity_${finding.final_severity || finding.severity}`]}`}>
                            {SEVERITY_ICONS[finding.final_severity || finding.severity]}{" "}
                            {(finding.final_severity || finding.severity).toUpperCase()}
                          </span>
                          <code className={styles.headerName}>{finding.file}:{finding.line}</code>
                        </div>
                      </div>
                      <div className={styles.findingBody} style={{ display: 'block', borderTop: 'none', paddingTop: 0 }}>
                        <p className={styles.findingDesc}>{finding.description}</p>

                        {/* Snippet */}
                        {finding.raw_snippet && (
                          <div className="mt-3 p-3 rounded-lg border bg-secondary/50 border-border">
                            <div className="text-[10px] font-semibold uppercase tracking-wider mb-2 text-muted-foreground">Vulnerable Code</div>
                            <pre className="text-[11px] leading-relaxed whitespace-pre-wrap font-mono text-red-400">
                              {finding.raw_snippet}
                            </pre>
                          </div>
                        )}
                        
                        {/* Triage Reason */}
                        {finding.triage_reason && (
                          <div className="mt-3 p-3 rounded-lg border bg-blue-500/5 border-blue-500/20">
                            <div className="text-[10px] font-semibold uppercase tracking-wider mb-1 text-blue-400">AI Triage Analysis</div>
                            <p className="text-xs leading-relaxed text-foreground/80">{finding.triage_reason}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Generated Fixes / Remediation */}
            {staticFixes.length > 0 && (
              <div className="mb-8">
                <h3 className="text-sm font-semibold mb-4 text-cyan-400 border-b border-cyan-500/20 pb-2 flex items-center gap-2">
                  <Wrench size={16} /> AI-Generated Remediation ({staticFixes.length})
                </h3>
                <div className="grid gap-4">
                  {staticFixes.map((fix, i) => {
                    const related = staticFindings.find((f) => f.db_id === fix.finding_id);
                    return (
                      <div key={i} className="p-4 rounded-xl border border-cyan-500/20 bg-cyan-500/5">
                        <div className="flex items-center gap-2 mb-2">
                          <Wrench className="h-4 w-4 text-cyan-400" />
                          <span className="font-semibold text-sm text-cyan-100">
                            Fix #{i + 1}{related ? ` — ${related.file}:${related.line}` : ""}
                          </span>
                        </div>
                        {fix.explanation && (
                          <p className="text-sm text-cyan-100/80 mb-3">{fix.explanation}</p>
                        )}
                        <div className="p-3 rounded-lg bg-background border border-border">
                          <div className="text-[10px] font-semibold uppercase tracking-wider mb-2 text-muted-foreground">Suggested Fix</div>
                          <pre className="text-[11px] leading-relaxed whitespace-pre-wrap font-mono text-green-400">
                            {fix.diff_text}
                          </pre>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Safe Patterns / Security Controls */}
            <div>
              <h3 className="text-sm font-semibold mb-4 text-green-400 border-b border-green-500/20 pb-2 flex items-center gap-2">
                <Shield size={16} /> Verified Security Controls
              </h3>
              {safePatterns.length === 0 ? (
                <div className="text-sm text-muted-foreground italic px-4 py-3 bg-secondary/30 rounded-lg border border-border">
                  No explicit safe patterns or security controls were detected in the codebase.
                </div>
              ) : (
                <div className="grid gap-4">
                  {safePatterns.map((pattern, i) => (
                    <div key={i} className="p-4 rounded-xl border border-green-500/20 bg-green-500/5">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Check className="h-4 w-4 text-green-500" />
                          <span className="font-semibold text-sm text-green-100">{pattern.type.replace(/_/g, ' ').toUpperCase()}</span>
                        </div>
                        <code className="text-xs text-muted-foreground bg-background px-2 py-1 rounded">{pattern.path}:{pattern.line}</code>
                      </div>
                      <p className="text-sm text-green-100/80 mb-3">{pattern.description}</p>
                      
                      <div className="p-3 rounded-lg bg-background border border-border">
                        <div className="text-[10px] font-semibold uppercase tracking-wider mb-2 text-muted-foreground">Safe Implementation</div>
                        <pre className="text-[11px] leading-relaxed whitespace-pre-wrap font-mono text-green-400">
                          {pattern.snippet}
                        </pre>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
            
          </section>
        )}
      </div>
    </DashboardLayout>
  );
}
