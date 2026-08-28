"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  AlertTriangle, AlertCircle, AlertOctagon, Info, ShieldAlert,
  Key, Zap, FileCode, FormInput, LayoutDashboard, HelpCircle,
  Shield, Map, Lock, Globe, Clock, ChevronDown, ChevronRight, FileText, Check
} from "lucide-react";
import type { FullScanResponse, ReconResponse, Endpoint, HeaderFinding, InjectionReport, InjectionFinding } from "@/lib/api";
import styles from "../dashboard/dashboard.module.css";

type ScanData = FullScanResponse | ReconResponse;

function isFullScan(data: ScanData): data is FullScanResponse {
  return "header_audit_report" in data;
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
  
  const [activeTab, setActiveTab] = useState<"surface" | "headers" | "injection">("surface");
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
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
      } else if (history.length > 0) {
        setActiveScanId(history[0].id);
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

  const endpoints: Endpoint[] = surfaceReport?.endpoints || [];
  const findings: HeaderFinding[] = auditReport?.findings || [];
  const filteredFindings =
    filterSeverity === "all"
      ? findings
      : findings.filter((f) => f.severity === filterSeverity);

  // Severity counts
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
              setActiveScanId(e.target.value);
              setActiveTab("surface");
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
              {scanMode === "full" ? "Full Scan" : scanMode === "injection" ? "Injection Test" : "Recon Only"}
            </div>
            <h1 className={styles.dashTitle}>Report Overview</h1>
            <div className={styles.dashMeta}>
              <span className={styles.dashMetaItem}>
                <span className={styles.dashMetaIcon}><Globe size={14} /></span>
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

        {/* ── Summary Stats ── */}
        <div className={styles.statsRow}>
          <div className={styles.statCard}>
            <div className={styles.statValue}>{surfaceReport?.total_endpoints ?? 0}</div>
            <div className={styles.statLabel}>Endpoints Found</div>
          </div>
          {auditReport && (
            <>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{auditReport.total_findings}</div>
                <div className={styles.statLabel}>Total Findings</div>
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
        </div>

        {/* ── LLM Executive Summary ── */}
        {auditReport?.summary && (
          <div className={styles.summaryCard}>
            <div className={styles.summaryCardHeader}>
              <span className={styles.summaryIcon}>🤖</span>
              <span className={styles.summaryTitle}>AI Executive Summary</span>
            </div>
            <p className={styles.summaryText}>{auditReport.summary}</p>
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
        {auditReport && (
          <div className={styles.tabs}>
            <button
              className={`${styles.tab} ${activeTab === "surface" ? styles.tabActive : ""}`}
              onClick={() => setActiveTab("surface")}
            >
              <Map size={16} className="mr-2 inline" /> Attack Surface
              <span className={styles.tabCount}>{surfaceReport?.total_endpoints ?? 0}</span>
            </button>
            <button
              className={`${styles.tab} ${activeTab === "headers" ? styles.tabActive : ""}`}
              onClick={() => setActiveTab("headers")}
            >
              <Lock size={16} className="mr-2 inline" /> Header Audit
              <span className={`${styles.tabCount} ${auditReport.total_findings > 0 ? styles.tabCountAlert : ""}`}>
                {auditReport.total_findings}
              </span>
            </button>
            {injectionReport && (
              <button
                className={`${styles.tab} ${activeTab === "injection" ? styles.tabActive : ""}`}
                onClick={() => setActiveTab("injection")}
              >
                <Zap size={16} className="mr-2 inline" /> Injection Test
                <span className={`${styles.tabCount} ${injectionReport.total_confirmed > 0 ? styles.tabCountAlert : ""}`}>
                  {injectionReport.total_confirmed}
                </span>
              </button>
            )}
          </div>
        )}

        {/* ── Surface Report Tab ── */}
        {(!auditReport || activeTab === "surface") && (
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
                  {endpoints.map((ep, i) => (
                    <tr key={i} className={styles.tableRow}>
                      <td>
                        <span className={`${styles.epTypeBadge} ${styles[`epType_${ep.endpoint_type}`]} flex items-center gap-1.5`}>
                          {ENDPOINT_TYPE_ICONS[ep.endpoint_type] || <HelpCircle size={14} />}
                          {ep.endpoint_type?.replace(/_/g, " ") || "unknown"}
                        </span>
                      </td>
                      <td className={styles.urlCell} title={ep.url}>
                        <div className="flex items-center gap-2">
                          <a href={ep.url} target="_blank" rel="noopener noreferrer" className={styles.urlLink}>
                            {ep.url.length > 50 ? ep.url.slice(0, 50) + "…" : ep.url}
                          </a>
                          {ep.is_interesting && (
                            <span className="bg-yellow-500/20 text-yellow-500 text-[10px] px-1.5 py-0.5 rounded flex items-center gap-1 font-medium"><AlertTriangle size={10} /> Flagged</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className={`${styles.methodBadge} ${styles[`method_${ep.method?.toLowerCase()}`]}`}>
                          {ep.method}
                        </span>
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
                            {ep.technology.map((t, i) => (
                              <span key={i} className="px-1.5 py-0.5 bg-secondary text-[10px] rounded border border-border/50">{t}</span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="text-xs max-w-[200px]">
                        {ep.parameters && ep.parameters.length > 0 && (
                          <div className="flex flex-wrap gap-1 mb-1">
                            {ep.parameters.map((p, i) => (
                              <span key={i} className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 rounded border border-blue-500/20 text-[10px]">{p}=?</span>
                            ))}
                          </div>
                        )}
                        {ep.form_inputs && ep.form_inputs.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            <span className="text-muted-foreground text-[10px] flex items-center">Inputs:</span>
                            {ep.form_inputs.map((inp, i) => (
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

              {/* Severity filter */}
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

            {filteredFindings.length === 0 ? (
              <div className={styles.noFindings}>
                <Check className="h-5 w-5 text-green-500 mr-2 inline" /> No findings for the selected severity level
              </div>
            ) : (
              <div className={styles.findingsList}>
                {filteredFindings.map((finding, i) => (
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
                            <span className={styles.findingMetaLabel}>Expected</span>
                            <code className={styles.findingMetaCode}>{finding.expected}</code>
                          </div>
                          <div className={styles.findingMetaItem}>
                            <span className={styles.findingMetaLabel}>Actual</span>
                            <code
                              className={`${styles.findingMetaCode} ${finding.actual === "MISSING" ? styles.findingMissing : ""}`}
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
              <div className={`${styles.statCard} ${styles.statCard_critical}`}>
                <div className={`${styles.statValue}`} style={{ WebkitTextFillColor: '#ef4444' }}>{injectionReport.total_confirmed}</div>
                <div className={styles.statLabel}>Confirmed Vulnerabilities</div>
              </div>
              <div className={styles.statCard}>
                <div className={styles.statValue}>{injectionReport.total_discarded}</div>
                <div className={styles.statLabel}>Discarded (False Positives)</div>
              </div>
            </div>

            {/* AI Summary */}
            {injectionReport.summary && (
              <div className={styles.summaryCard + " mb-6"}>
                <div className={styles.summaryCardHeader}>
                  <span className={styles.summaryTitle}>AI Executive Summary</span>
                </div>
                <p className={styles.summaryText}>{injectionReport.summary}</p>
              </div>
            )}

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

            {/* Findings list */}
            {injectionFindings.length === 0 ? (
              <div className={styles.noFindings}>
                <Check className="h-5 w-5 text-green-500 mr-2 inline" /> No injection vulnerabilities confirmed. Tested endpoints appear resilient.
              </div>
            ) : (
              <div className={styles.findingsList}>
                {injectionFindings.map((finding, i) => (
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
                            <span className={styles.findingMetaLabel}>Payload</span>
                            <code className={styles.findingMetaCode}>{finding.payload_name}</code>
                          </div>
                        </div>

                        {/* Evidence */}
                        {finding.evidence && (
                          <div className="mt-3 p-3 rounded-lg border" style={{ background: 'rgba(239,68,68,0.05)', borderColor: 'rgba(239,68,68,0.2)' }}>
                            <div className="text-[10px] font-semibold uppercase tracking-wider mb-1" style={{ color: 'rgba(239,68,68,0.7)' }}>Evidence</div>
                            <p className="text-xs leading-relaxed" style={{ color: 'rgba(255,255,255,0.7)' }}>{finding.evidence}</p>
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
          </section>
        )}
      </div>
    </DashboardLayout>
  );
}
