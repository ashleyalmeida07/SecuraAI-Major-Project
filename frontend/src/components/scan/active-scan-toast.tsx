"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Loader2, ArrowRight, CheckCircle2, XCircle, X } from "lucide-react";
import { useScanContext } from "@/contexts/scan-context";
import { useActiveScan } from "@/contexts/active-scan-context";
import { flowByMode } from "@/lib/scan-flows";

/** Toast for existing flows: static / recon / full / injection */
function LegacyScanToast() {
  const { activeMode, getState } = useScanContext();
  const pathname = usePathname();

  if (!activeMode) return null;

  const activeHref = `/scan/${activeMode === "full" ? "full" : activeMode}`;
  if (pathname === activeHref) return null;

  const flow = flowByMode(activeMode);
  const state = getState(activeMode);
  const Icon = flow.icon;

  return (
    <Link
      href={activeHref}
      className="fixed bottom-6 right-6 z-50 flex items-center gap-4 rounded-lg border border-border/50 bg-card/95 p-4 shadow-xl backdrop-blur-sm transition-transform hover:-translate-y-1"
    >
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-secondary">
        <Icon className="h-5 w-5" style={{ color: flow.accent }} />
      </div>
      <div className="flex flex-col">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold">{flow.short} Running</span>
          <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
        </div>
        <span className="text-xs text-muted-foreground line-clamp-1 max-w-[200px]">
          {state.activity || "Initializing..."}
        </span>
      </div>
      <ArrowRight className="h-4 w-4 text-muted-foreground ml-2" />
    </Link>
  );
}

/** Floating banner for LLM Audit / BaaS Audit (use ActiveScanContext) */
function NewScanBanner() {
  const { phase, scanType, scanHref, activity, progressPct, accentColor, resetScan } = useActiveScan();
  const pathname = usePathname();

  if (phase === "idle") return null;
  // Don't show if we're already on that page AND scan is running (done/error always show)
  if (phase === "scanning" && pathname === scanHref) return null;

  const isDone    = phase === "done";
  const isError   = phase === "error";
  const isRunning = phase === "scanning";

  return (
    <div
      className="fixed bottom-6 right-6 z-50 flex flex-col overflow-hidden rounded-xl shadow-2xl"
      style={{
        width: 320,
        background: "#0d0d0f",
        border: `1px solid ${accentColor}35`,
        boxShadow: `0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px ${accentColor}18`,
      }}
    >
      {/* Progress bar */}
      <div className="h-[3px] w-full bg-white/5">
        <div
          className="h-full transition-all duration-700 ease-out"
          style={{ width: `${progressPct}%`, background: accentColor }}
        />
      </div>

      {/* Content row */}
      <div className="flex items-start gap-3 px-4 py-3">
        {/* Icon */}
        <div className="mt-0.5 shrink-0">
          {isRunning && <Loader2 className="h-4 w-4 animate-spin" style={{ color: accentColor }} />}
          {isDone    && <CheckCircle2 className="h-4 w-4 text-emerald-400" />}
          {isError   && <XCircle className="h-4 w-4 text-red-400" />}
        </div>

        {/* Text */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-bold uppercase tracking-wider" style={{ color: accentColor }}>
              {scanType}
            </span>
            {isRunning && (
              <span className="rounded-full bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-white/40">
                {progressPct}%
              </span>
            )}
            {isDone  && <span className="rounded-full bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400">Complete</span>}
            {isError && <span className="rounded-full bg-red-500/10    px-1.5 py-0.5 text-[10px] font-semibold text-red-400">Failed</span>}
          </div>
          <p className="mt-0.5 truncate text-[12px] leading-relaxed text-white/50">{activity}</p>
        </div>

        {/* Actions */}
        <div className="flex shrink-0 items-center gap-1">
          {scanHref && (
            <Link
              href={scanHref}
              className="flex h-7 w-7 items-center justify-center rounded-md"
              style={{ color: "rgba(255,255,255,0.4)" }}
              title="Go to scan"
            >
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          )}
          <button
            onClick={resetScan}
            className="flex h-7 w-7 items-center justify-center rounded-md"
            style={{ color: "rgba(255,255,255,0.3)" }}
            title="Dismiss"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Animated pulse strip when running */}
      {isRunning && (
        <div
          className="h-px w-full animate-pulse"
          style={{ background: `linear-gradient(90deg, transparent, ${accentColor}60, transparent)` }}
        />
      )}
    </div>
  );
}

/** Composite — renders whichever banner is relevant */
export function ActiveScanToast() {
  const { activeMode } = useScanContext();
  const { phase } = useActiveScan();

  // New context takes priority (LLM / BaaS)
  if (phase !== "idle") return <NewScanBanner />;
  // Fall back to legacy toast for other flows
  if (activeMode) return <LegacyScanToast />;
  return null;
}
