"use client";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { ScanRunner } from "@/components/scan/scan-runner";

export default function InjectionScanPage() {
  return (
    <DashboardLayout activeId="scan-injection">
      <ScanRunner mode="injection" />
    </DashboardLayout>
  );
}
