"use client";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { ScanRunner } from "@/components/scan/scan-runner";

export default function ReconScanPage() {
  return (
    <DashboardLayout activeId="scan-recon">
      <ScanRunner mode="recon" />
    </DashboardLayout>
  );
}
