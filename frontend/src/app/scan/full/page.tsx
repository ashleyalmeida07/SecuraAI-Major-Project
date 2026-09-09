"use client";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { ScanRunner } from "@/components/scan/scan-runner";

export default function FullScanPage() {
  return (
    <DashboardLayout activeId="scan-headers">
      <ScanRunner mode="full" />
    </DashboardLayout>
  );
}
