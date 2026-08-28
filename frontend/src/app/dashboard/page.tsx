"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { isAuthenticated, logout } from "@/utils/auth";
import type { FullScanResponse, ReconResponse, Endpoint, HeaderFinding } from "@/lib/api";
import styles from "./dashboard.module.css";

type ScanData = FullScanResponse | ReconResponse;

function isFullScan(data: ScanData): data is FullScanResponse {
  return "header_audit_report" in data;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_ICONS: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "🟣",
};

const ENDPOINT_TYPE_ICONS: Record<string, string> = {
  auth_page: "🔐",
  api: "⚡",
  static_asset: "📁",
  form: "📝",
  dashboard: "📊",
  unknown: "❓",
};

export default function DashboardPage() {
  const router = useRouter();
  const [scanData, setScanData] = useState<ScanData | null>(null);
  const [scanMode, setScanMode] = useState<string>("full");
  const [scanUrl, setScanUrl] = useState<string>("");
  const [activeTab, setActiveTab] = useState<"surface" | "headers">("surface");
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("all");

  useEffect(() => {
    if (!isAuthenticated()) {
      router.push("/login");
      return;
    }

    const raw = sessionStorage.getItem("authtrack_scan_result");
    const mode = sessionStorage.getItem("authtrack_scan_mode") || "full";
    const url = sessionStorage.getItem("authtrack_scan_url") || "";
    if (raw) {
      setScanData(JSON.parse(raw));
      setScanMode(mode);
      setScanUrl(url);
    }
  }, [router]);

  if (!scanData) {
    return (
      <div className={styles.noData}>
        <div className={styles.noDataCard}>
          <div className={styles.noDataIcon}>🛡️</div>
          <h1 className={styles.noDataTitle}>No Scan Results</h1>
          <p className={styles.noDataDesc}>
            Run a scan first to see results here.
          </p>
          <Link href="/scan" className={styles.noDataBtn}>
            🚀 Go to Scanner
          </Link>
        </div>
      </div>
    );
  }

  const surfaceReport = scanData.surface_report;
  const auditReport = isFullScan(scanData) ? scanData.header_audit_report : null;
  const scanErrors = scanData.errors || [];

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

  const scanTs = surfaceReport?.scan_timestamp
    ? new Date(surfaceReport.scan_timestamp).toLocaleString()
    : "—";

  return (
    <div className={styles.page}>
      {/* ── Nav ── */}
      <nav className={styles.nav}>
        <div className={styles.navInner}>
          <Link href="/" className={styles.navLogo}>
            <span>🛡️</span>
            <span className={styles.navBrand}>AuthTrack</span>
          </Link>
          <div className={styles.navRight}>
            <Link href="/scan" className={styles.navScanBtn}>
              ➕ New Scan
            </Link>
            <button className={styles.navLogoutBtn} onClick={logout}>
              Logout
            </button>
          </div>
        </div>
      </nav>

      <main className={styles.main}>
        {/* ── Dashboard Header ── */}
        <div className={styles.dashHeader}>
          <div className={styles.dashHeaderLeft}>
            <div className={styles.dashBadge}>
              {scanMode === "full" ? "Full Scan" : "Recon Only"}
            </div>
            <h1 className={styles.dashTitle}>Scan Results</h1>
            <div className={styles.dashMeta}>
              <span className={styles.dashMetaItem}>
                <span className={styles.dashMetaIcon}>🌐</span>
                <code className={styles.dashUrl}>{scanUrl}</code>
              </span>
              <span className={styles.dashMetaDivider}>·</span>
              <span className={styles.dashMetaItem}>
                <span className={styles.dashMetaIcon}>🕐</span>
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
              {scanErrors.map((err, i) => (
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
              🗺️ Attack Surface
              <span className={styles.tabCount}>{surfaceReport?.total_endpoints ?? 0}</span>
            </button>
            <button
              className={`${styles.tab} ${activeTab === "headers" ? styles.tabActive : ""}`}
              onClick={() => setActiveTab("headers")}
            >
              🔒 Header Audit
              <span className={`${styles.tabCount} ${auditReport.total_findings > 0 ? styles.tabCountAlert : ""}`}>
                {auditReport.total_findings}
              </span>
            </button>
          </div>
        )}

        {/* ── Surface Report Tab ── */}
        {(!auditReport || activeTab === "surface") && (
          <section className={styles.section}>
            <h2 className={styles.sectionTitle}>🗺️ Attack Surface Map</h2>

            {/* Type breakdown */}
            <div className={styles.typeBreakdown}>
              {Object.entries(typeCounts).map(([type, count]) => (
                <div key={type} className={styles.typeCard}>
                  <span className={styles.typeIcon}>{ENDPOINT_TYPE_ICONS[type] || "❓"}</span>
                  <span className={styles.typeCount}>{count}</span>
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
                    <th>Content-Type</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((ep, i) => (
                    <tr key={i} className={styles.tableRow}>
                      <td>
                        <span className={`${styles.epTypeBadge} ${styles[`epType_${ep.endpoint_type}`]}`}>
                          {ENDPOINT_TYPE_ICONS[ep.endpoint_type] || "❓"}{" "}
                          {ep.endpoint_type?.replace(/_/g, " ") || "unknown"}
                        </span>
                      </td>
                      <td className={styles.urlCell} title={ep.url}>
                        <a href={ep.url} target="_blank" rel="noopener noreferrer" className={styles.urlLink}>
                          {ep.url.length > 60 ? ep.url.slice(0, 60) + "…" : ep.url}
                        </a>
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
                      <td className={styles.contentType}>{ep.content_type || "—"}</td>
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
            <div className={styles.auditHeader}>
              <h2 className={styles.sectionTitle}>🔒 Security Header Audit</h2>

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
                ✅ No findings for the selected severity level
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
                        {expandedFinding === i ? "▲" : "▼"}
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
      </main>
    </div>
  );
}
