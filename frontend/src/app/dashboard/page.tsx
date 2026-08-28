"use client";

import { useEffect, useState, Suspense } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  Shield, Globe, Clock, Activity, ArrowRight
} from "lucide-react";

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

    const historyRaw = localStorage.getItem("authtrack_scan_history");
    if (historyRaw) {
      setScans(JSON.parse(historyRaw));
    }
  }, [router]);

  if (!mounted) return null;

  return (
    <DashboardLayout activeId="dashboard">
      <div className="max-w-6xl mx-auto flex flex-col gap-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground tracking-tight">Dashboard</h1>
          <p className="mt-2 text-sm text-muted-foreground">Overview of your recent security scans.</p>
        </div>

        {scans.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 bg-card border border-border rounded-xl shadow-sm">
            <Shield size={48} className="text-muted-foreground/30 mb-4" />
            <h2 className="text-xl font-semibold mb-2">No Scan History</h2>
            <p className="text-muted-foreground text-sm mb-6 text-center max-w-sm">
              You haven't run any security scans yet. Start a new scan to see the results here.
            </p>
            <Link href="/scan" className="bg-white text-black hover:bg-neutral-200 font-medium px-6 py-2.5 rounded-md transition-colors">
              Run New Scan
            </Link>
          </div>
        ) : (
          <div className="grid gap-4">
            {scans.map((scan) => {
              const totalEndpoints = scan.data?.surface_report?.total_endpoints || 0;
              const totalFindings = scan.data?.header_audit_report?.total_findings || 0;
              
              return (
                <div key={scan.id} className="bg-card border border-border rounded-lg p-5 flex flex-col sm:flex-row gap-4 sm:items-center justify-between hover:border-primary/50 transition-colors">
                  <div className="flex items-start gap-4">
                    <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                      <Activity className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-base flex items-center gap-2">
                        {scan.url}
                        <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-secondary text-muted-foreground">
                          {scan.mode}
                        </span>
                      </h3>
                      <div className="flex items-center gap-4 mt-2 text-sm text-muted-foreground">
                        <span className="flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" /> {new Date(scan.timestamp).toLocaleString()}</span>
                        <span className="flex items-center gap-1.5"><Globe className="h-3.5 w-3.5" /> {totalEndpoints} Endpoints</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-6 mt-4 sm:mt-0 pt-4 sm:pt-0 border-t sm:border-t-0 border-border">
                    {scan.mode === "full" && (
                      <div className="text-center sm:text-right">
                        <div className="text-2xl font-bold text-foreground">{totalFindings}</div>
                        <div className="text-xs text-muted-foreground uppercase tracking-wider">Findings</div>
                      </div>
                    )}
                    
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
        )}
      </div>
    </DashboardLayout>
  );
}
