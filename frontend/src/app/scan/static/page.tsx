"use client";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { ScanRunner } from "@/components/scan/scan-runner";

export default function StaticScanPage() {
  return (
    <DashboardLayout activeId="scan-static">
      <ScanRunner mode="static" />
    </DashboardLayout>
  );
}
