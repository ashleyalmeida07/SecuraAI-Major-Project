"use client";

/**
 * ActiveScanContext
 * Tracks whether ANY scan is currently running and what it is doing.
 * This context is consumed by DashboardLayout to show a floating
 * "scan in progress" banner that persists across page navigation.
 */

import React, { createContext, useContext, useState, useCallback } from "react";

export type ActiveScanPhase = "idle" | "scanning" | "done" | "error";

export interface ActiveScanState {
  phase: ActiveScanPhase;
  scanType: string;      // e.g. "LLM Audit", "BaaS Audit"
  scanHref: string;      // e.g. "/scan/llm-audit"
  activity: string;      // current node activity description
  progressPct: number;
  accentColor: string;   // hex color for the banner accent
}

interface ActiveScanContextValue extends ActiveScanState {
  startScan: (scanType: string, scanHref: string, accentColor: string) => void;
  updateScan: (activity: string, progressPct: number) => void;
  finishScan: (phase?: "done" | "error") => void;
  resetScan: () => void;
}

const DEFAULT: ActiveScanState = {
  phase: "idle",
  scanType: "",
  scanHref: "",
  activity: "",
  progressPct: 0,
  accentColor: "#6366f1",
};

const ActiveScanContext = createContext<ActiveScanContextValue>({
  ...DEFAULT,
  startScan: () => {},
  updateScan: () => {},
  finishScan: () => {},
  resetScan: () => {},
});

export function ActiveScanProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<ActiveScanState>(DEFAULT);

  const startScan = useCallback((scanType: string, scanHref: string, accentColor: string) => {
    setState({
      phase: "scanning",
      scanType,
      scanHref,
      activity: `Starting ${scanType}…`,
      progressPct: 5,
      accentColor,
    });
  }, []);

  const updateScan = useCallback((activity: string, progressPct: number) => {
    setState((prev) => ({ ...prev, activity, progressPct }));
  }, []);

  const finishScan = useCallback((phase: "done" | "error" = "done") => {
    setState((prev) => ({
      ...prev,
      phase,
      progressPct: phase === "done" ? 100 : prev.progressPct,
      activity: phase === "done" ? "Scan complete" : "Scan failed",
    }));
    // Auto-dismiss after 6 s
    setTimeout(() => {
      setState((prev) => (prev.phase === phase ? DEFAULT : prev));
    }, 6000);
  }, []);

  const resetScan = useCallback(() => setState(DEFAULT), []);

  return (
    <ActiveScanContext.Provider value={{ ...state, startScan, updateScan, finishScan, resetScan }}>
      {children}
    </ActiveScanContext.Provider>
  );
}

export function useActiveScan() {
  return useContext(ActiveScanContext);
}

