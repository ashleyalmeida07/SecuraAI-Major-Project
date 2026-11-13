"use client";

/**
 * ScanBanner — floating bottom-right pill that shows when a scan is running.
 * Rendered inside DashboardLayout so it appears on every page.
 */

import React from "react";
import Link from "next/link";
import { Loader2, CheckCircle2, XCircle, ArrowRight, X } from "lucide-react";
import { useActiveScan } from "@/contexts/active-scan-context";

export function ScanBanner() {
  const { phase, scanType, scanHref, activity, progressPct, accentColor, resetScan } = useActiveScan();

  if (phase === "idle") return null;

  const isDone  = phase === "done";
  const isError = phase === "error";
  const isRunning = phase === "scanning";

  return (
    <div
      className="fixed bottom-5 right-5 z-[80] flex flex-col gap-0 overflow-hidden rounded-xl shadow-2xl"
      style={{
        width: 320,
        background: "#0d0d0f",
        border: `1px solid ${accentColor}35`,
        boxShadow: `0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px ${accentColor}18`,
      }}
    >
      {/* Progress bar at top */}
      <div className="h-[3px] w-full bg-white/5">
        <div
          className="h-full transition-all duration-700 ease-out"
          style={{ width: `${progressPct}%`, background: accentColor }}
        />
      </div>

      {/* Content */}
      <div className="flex items-start gap-3 px-4 py-3">
        {/* Status icon */}
        <div className="mt-0.5 shrink-0">
          {isRunning && (
            <Loader2
              className="h-4 w-4 animate-spin"
              style={{ color: accentColor }}
            />
          )}
          {isDone && <CheckCircle2 className="h-4 w-4 text-emerald-400" />}
          {isError && <XCircle className="h-4 w-4 text-red-400" />}
        </div>

        {/* Text */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span
              className="text-[11px] font-bold uppercase tracking-wider"
              style={{ color: accentColor }}
            >
              {scanType}
            </span>
            {isRunning && (
              <span className="rounded-full bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-white/40">
                {progressPct}%
              </span>
            )}
            {isDone && (
              <span className="rounded-full bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400">
                Complete
              </span>
            )}
            {isError && (
              <span className="rounded-full bg-red-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-red-400">
                Failed
              </span>
            )}
          </div>
          <p className="mt-0.5 truncate text-[12px] leading-relaxed text-white/50">
            {activity}
          </p>
        </div>

        {/* Actions */}
        <div className="flex shrink-0 items-center gap-1">
          {scanHref && (
            <Link
              href={scanHref}
              className="flex h-7 w-7 items-center justify-center rounded-md transition-colors hover:bg-white/8"
              title="Go to scan"
              style={{ color: "rgba(255,255,255,0.4)" }}
            >
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          )}
          <button
            onClick={resetScan}
            className="flex h-7 w-7 items-center justify-center rounded-md transition-colors hover:bg-white/8"
            title="Dismiss"
            style={{ color: "rgba(255,255,255,0.3)" }}
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Running pulse strip */}
      {isRunning && (
        <div
          className="h-px w-full animate-pulse"
          style={{ background: `linear-gradient(90deg, transparent, ${accentColor}60, transparent)` }}
        />
      )}
    </div>
  );
}

