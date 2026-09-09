"use client";

export const dynamic = "force-dynamic";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { isAuthenticated } from "@/utils/auth";
import { 
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, 
  CartesianGrid, Tooltip, Legend, ResponsiveContainer 
} from "recharts";
import { Activity, ShieldAlert, Globe, Hash } from "lucide-react";

export default function AnalyticsPage() {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);
  const [stats, setStats] = useState({
    totalScans: 0,
    totalEndpoints: 0,
    totalFindings: 0,
  });
  
  const [severityData, setSeverityData] = useState<any[]>([]);
  const [endpointData, setEndpointData] = useState<any[]>([]);

  const SEVERITY_COLORS = {
    Critical: "#ef4444",
    High: "#f97316",
    Medium: "#eab308",
    Low: "#3b82f6",
  };

  const ENDPOINT_COLORS = {
    auth_page: "#a855f7",
    api: "#3b82f6",
    static_asset: "#22c55e",
    dashboard: "#f97316",
    unknown: "#6b7280"
  };

  useEffect(() => {
    setMounted(true);
    if (!isAuthenticated()) {
      router.push("/login");
      return;
    }

    const historyRaw = localStorage.getItem("SecuraAI_scan_history");
    if (historyRaw) {
      const scans = JSON.parse(historyRaw);
      
      let endpts = 0;
      let findings = 0;
      
      const severityCounts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      const endpointCounts: Record<string, number> = { auth_page: 0, api: 0, static_asset: 0, dashboard: 0, unknown: 0 };

      scans.forEach((scan: any) => {
        // Count endpoints
        if (scan.data?.surface_report) {
          endpts += scan.data.surface_report.total_endpoints || 0;
          
          scan.data.surface_report.endpoints?.forEach((ep: any) => {
            const type = ep.endpoint_type || "unknown";
            endpointCounts[type] = (endpointCounts[type] || 0) + 1;
          });
        }
        
        // Count findings
        const allFindings = [
          ...(scan.data?.header_audit_report?.findings || []),
          ...(scan.data?.injection_report?.findings || [])
        ];
        
        findings += allFindings.length;
        allFindings.forEach((finding: any) => {
          const sev = finding.severity || "Low";
          severityCounts[sev] = (severityCounts[sev] || 0) + 1;
        });
      });

      setStats({
        totalScans: scans.length,
        totalEndpoints: endpts,
        totalFindings: findings,
      });

      // Format for recharts
      setSeverityData([
        { name: "Critical", value: severityCounts.Critical },
        { name: "High", value: severityCounts.High },
        { name: "Medium", value: severityCounts.Medium },
        { name: "Low", value: severityCounts.Low },
      ].filter(d => d.value > 0));

      const epData = Object.keys(endpointCounts).map(key => ({
        name: key.replace("_", " ").toUpperCase(),
        count: endpointCounts[key],
        rawKey: key
      })).filter(d => d.count > 0);
      
      setEndpointData(epData);
    }
  }, [router]);

  if (!mounted) return null;

  return (
    <DashboardLayout activeId="analytics">
      <div className="max-w-6xl mx-auto flex flex-col gap-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground tracking-tight">Analytics Overview</h1>
          <p className="mt-2 text-sm text-muted-foreground">Aggregated data and metrics across all your security scans.</p>
        </div>

        {/* Top Stats Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-card border border-border p-6 rounded-xl shadow-sm flex flex-col gap-2">
            <div className="flex items-center gap-2 text-muted-foreground font-medium text-sm">
              <Activity className="h-4 w-4" /> Total Scans Run
            </div>
            <div className="text-4xl font-bold text-foreground">{stats.totalScans}</div>
          </div>
          
          <div className="bg-card border border-border p-6 rounded-xl shadow-sm flex flex-col gap-2">
            <div className="flex items-center gap-2 text-muted-foreground font-medium text-sm">
              <Globe className="h-4 w-4" /> Endpoints Mapped
            </div>
            <div className="text-4xl font-bold text-foreground">{stats.totalEndpoints}</div>
          </div>

          <div className="bg-card border border-border p-6 rounded-xl shadow-sm flex flex-col gap-2">
            <div className="flex items-center gap-2 text-muted-foreground font-medium text-sm">
              <ShieldAlert className="h-4 w-4" /> Total Vulnerabilities
            </div>
            <div className="text-4xl font-bold text-foreground">{stats.totalFindings}</div>
          </div>
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-4">
          
          {/* Findings by Severity Pie Chart */}
          <div className="bg-card border border-border p-6 rounded-xl shadow-sm">
            <h2 className="text-lg font-semibold mb-6">Findings by Severity</h2>
            {severityData.length > 0 ? (
              <div className="h-[300px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={70}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                      stroke="none"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS]} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#141418', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                      itemStyle={{ color: '#fff' }}
                    />
                    <Legend verticalAlign="bottom" height={36} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-muted-foreground">
                <p>No vulnerabilities found yet.</p>
              </div>
            )}
          </div>

          {/* Attack Surface Breakdown Bar Chart */}
          <div className="bg-card border border-border p-6 rounded-xl shadow-sm">
            <h2 className="text-lg font-semibold mb-6">Attack Surface Breakdown</h2>
            {endpointData.length > 0 ? (
              <div className="h-[300px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={endpointData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                    <XAxis dataKey="name" stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 12 }} />
                    <YAxis stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 12 }} allowDecimals={false} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#141418', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                      itemStyle={{ color: '#fff' }}
                      cursor={{ fill: 'rgba(255,255,255,0.02)' }}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {endpointData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={ENDPOINT_COLORS[entry.rawKey as keyof typeof ENDPOINT_COLORS] || ENDPOINT_COLORS.unknown} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-muted-foreground">
                <p>No endpoints mapped yet.</p>
              </div>
            )}
          </div>

        </div>
      </div>
    </DashboardLayout>
  );
}
