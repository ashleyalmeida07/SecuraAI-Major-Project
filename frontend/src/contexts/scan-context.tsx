"use client";

/**
 * ScanContext — global store for all four scan flows.
 *
 * By lifting scan state here (root layout level), navigating away from a scan
 * page no longer destroys the in-flight stream. A floating toast notifies the
 * user when a scan is active, and clicking it returns them to that scan.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
} from "react";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import {
  scanFullStream,
  scanInjectionStream,
  scanReconStream,
  scanStaticStream,
} from "@/lib/api";
import type { NodeResult, NodeStatus } from "@/components/ui/scan-pipeline";
import {
  FLOW_NODES,
  STATIC_NODE_IDS,
  STATIC_SCANNER_IDS,
  staticNodeId,
  type ScanMode,
} from "@/lib/scan-flows";
import { parseFlowNode, parseStaticNode, type TriageAcc } from "@/components/scan/event-parsers";

// ─── per-mode state shape ──────────────────────────────────────────────────────
export interface ScanRunState {
  scanning: boolean;
  scanComplete: boolean;
  error: string | null;
  activity: string;
  doneNodes: string[];
  results: Record<string, NodeResult>;
  scanId: string | null;
  /** raw per-node backend states, used to rebuild the report */
  rawStates: Record<string, any>;
  triageAcc: TriageAcc;
}

const defaultState = (): ScanRunState => ({
  scanning: false,
  scanComplete: false,
  error: null,
  activity: "",
  doneNodes: [],
  results: {},
  scanId: null,
  rawStates: {},
  triageAcc: { confirmed: 0, discarded: 0, done: 0, total: 0 },
});

// ─── context shape ─────────────────────────────────────────────────────────────
interface ScanContextValue {
  getState: (mode: ScanMode) => ScanRunState;
  start: (mode: ScanMode, options: StartOptions) => Promise<void>;
  reset: (mode: ScanMode) => void;
  /** Which mode has an active scan (for the toast) */
  activeMode: ScanMode | null;
}

export interface StartOptions {
  target: string;
  maxDepth?: number;
  maxPages?: number;
  includeCodeql?: boolean;
  maxTriage?: number;
}

const ScanContext = createContext<ScanContextValue | null>(null);

// ─── helpers (duplicated from use-scan-run so context is self-contained) ───────
const now = () =>
  new Date().toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

const nodeIds = (mode: ScanMode): string[] =>
  mode === "static"
    ? STATIC_NODE_IDS
    : (FLOW_NODES[mode as Exclude<ScanMode, "static">]?.map((n) => n.id) ?? []);

function deriveStaticStatuses(done: Set<string>, running: boolean): Record<string, NodeStatus> {
  const statuses: Record<string, NodeStatus> = {};
  const finished = done.has("report_builder");
  if (finished) { STATIC_NODE_IDS.forEach((id) => (statuses[id] = "done")); return statuses; }
  const active = (c: boolean): NodeStatus => (c && running ? "active" : "idle");
  const scannersDone = STATIC_SCANNER_IDS.every((id) => done.has(id));
  STATIC_SCANNER_IDS.forEach((id) => { statuses[id] = done.has(id) ? "done" : active(done.has("dispatch")); });
  statuses.merge_findings = done.has("merge_findings") ? "done" : active(scannersDone);
  statuses.retrieve_context = done.has("retrieve_context") ? "done" : active(done.has("merge_findings"));
  statuses.triage = done.has("fix_generator") ? "done" : active(done.has("retrieve_context"));
  statuses.fix_generator = done.has("fix_generator") ? "done" : active(done.has("triage"));
  statuses.report_builder = active(done.has("fix_generator"));
  return statuses;
}

function deriveFlowStatuses(ids: string[], done: Set<string>, running: boolean): Record<string, NodeStatus> {
  const statuses: Record<string, NodeStatus> = {};
  let pending = false;
  ids.forEach((id) => {
    if (done.has(id)) { statuses[id] = "done"; return; }
    statuses[id] = !pending && running ? "active" : "idle";
    pending = true;
  });
  return statuses;
}

// ─── provider ─────────────────────────────────────────────────────────────────
export function ScanProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();

  // One state entry per mode, stored as a ref so stream callbacks always see
  // the latest values without stale closures, then mirrored into React state
  // for re-renders.
  const storeRef = useRef<Record<ScanMode, ScanRunState>>({
    static: defaultState(),
    recon: defaultState(),
    full: defaultState(),
    injection: defaultState(),
  });

  const [, forceRender] = useState(0);
  const rerender = useCallback(() => forceRender((n) => n + 1), []);

  const patch = useCallback((mode: ScanMode, partial: Partial<ScanRunState>) => {
    storeRef.current[mode] = { ...storeRef.current[mode], ...partial };
    rerender();
  }, [rerender]);

  const getState = useCallback((mode: ScanMode) => storeRef.current[mode], []);

  const activeMode = useMemo<ScanMode | null>(() => {
    const modes: ScanMode[] = ["static", "recon", "full", "injection"];
    return modes.find((m) => storeRef.current[m].scanning) ?? null;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storeRef.current.static.scanning, storeRef.current.recon.scanning, storeRef.current.full.scanning, storeRef.current.injection.scanning]);

  const reset = useCallback((mode: ScanMode) => {
    patch(mode, defaultState());
  }, [patch]);

  const start = useCallback(async (mode: ScanMode, options: StartOptions) => {
    patch(mode, defaultState());
    patch(mode, { scanning: true });

    const ids = nodeIds(mode);
    const rawRef = storeRef.current[mode].rawStates;
    const triageRef = storeRef.current[mode].triageAcc;

    const handleEvent = (data: any) => {
      const current = storeRef.current[mode];

      if (data.event === "start" || data.event === "handoff" || data.event === "complete") {
        const updates: Partial<ScanRunState> = { activity: data.message };
        if (data.event === "complete" && data.scan_id) {
          updates.scanId = data.scan_id;
        }
        patch(mode, updates);
        return;
      }
      if (data.event === "error") {
        patch(mode, { error: data.message, activity: `Error: ${data.message}` });
        return;
      }
      if (data.event !== "node_update") return;

      const backendNode: string = data.node;
      rawRef[backendNode] = data.state;

      if (mode !== "static") {
        const newDone = current.doneNodes.includes(backendNode) ? current.doneNodes : [...current.doneNodes, backendNode];
        const parsed = parseFlowNode(backendNode, data.state);
        patch(mode, {
          doneNodes: newDone,
          results: { ...current.results, [backendNode]: { ...parsed, timestamp: now() } },
          activity: `${backendNode} — ${parsed.summary ?? "completed"}`,
        });
        return;
      }

      // static flow
      const nodeId = backendNode === "dispatch" ? "dispatch" : staticNodeId(backendNode);
      const newDone = current.doneNodes.includes(nodeId) ? current.doneNodes : [...current.doneNodes, nodeId];

      if (backendNode === "triage" && data.state?.triage_progress) {
        triageRef.total = data.state.triage_progress.total ?? triageRef.total;
        triageRef.done = data.state.triage_progress.done ?? triageRef.done;
      } else if (backendNode === "confirm_finding") {
        triageRef.confirmed += (data.state?.triaged_findings || []).length || 1;
      } else if (backendNode === "discard_finding") {
        triageRef.discarded += (data.state?.false_positives || []).length || 1;
      }

      const parsed = parseStaticNode(backendNode, data.state, triageRef);
      const newResults = nodeId === "dispatch" ? current.results : { ...current.results, [nodeId]: { ...parsed, timestamp: now() } };
      patch(mode, { doneNodes: newDone, results: newResults, activity: parsed.summary ?? backendNode });
    };

    try {
      const request = { url: options.target, max_depth: options.maxDepth, max_pages: options.maxPages };
      const staticReq = { target_path: options.target, include_codeql: options.includeCodeql ?? true, max_triage: options.maxTriage ?? 25 };

      if (mode === "static") await scanStaticStream(staticReq, handleEvent);
      else if (mode === "recon") await scanReconStream(request, handleEvent);
      else if (mode === "injection") await scanInjectionStream(request, handleEvent);
      else await scanFullStream(request, handleEvent);

      const finalDone = mode === "static" ? [...ids, "dispatch"] : [...ids];
      patch(mode, { doneNodes: finalDone, scanComplete: true, activity: "Scan complete — all nodes finished." });

      const finalScanId = storeRef.current[mode].scanId;
      toast.success(`${mode === 'static' ? 'Static Analysis' : mode === 'recon' ? 'Recon' : mode === 'full' ? 'Header Audit' : 'Injection Test'} completed!`, {
        description: "The results have been safely stored in your scan history.",
        action: finalScanId ? {
          label: "View Report",
          onClick: () => router.push(`/reports?id=${finalScanId}`)
        } : undefined,
        duration: 8000,
      });

      // Persist to sessionStorage for immediate report view
      try {
        const s = storeRef.current[mode].rawStates;
        sessionStorage.setItem("SecuraAI_scan_mode", mode);
        sessionStorage.setItem("SecuraAI_scan_url", options.target);
        sessionStorage.setItem("SecuraAI_scan_result", JSON.stringify(s));
      } catch { /* quota guard */ }
    } catch (err) {
      patch(mode, { error: err instanceof Error ? err.message : "Scan failed. Is the backend running?" });
    } finally {
      patch(mode, { scanning: false });
    }
  }, [patch]);

  return (
    <ScanContext.Provider value={{ getState, start, reset, activeMode }}>
      {children}
    </ScanContext.Provider>
  );
}

// ─── consumer hook ────────────────────────────────────────────────────────────
export function useScanContext() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScanContext must be used within <ScanProvider>");
  return ctx;
}

/** Derive the statuses map for a given mode's current state. */
export function useModeStatuses(mode: ScanMode): Record<string, NodeStatus> {
  const { getState } = useScanContext();
  const state = getState(mode);
  const done = new Set(state.doneNodes);
  const ids = nodeIds(mode);
  return mode === "static"
    ? deriveStaticStatuses(done, state.scanning)
    : deriveFlowStatuses(ids, done, state.scanning);
}

/** Progress percentage for the progress bar. */
export function useModeProgress(mode: ScanMode): number {
  const { getState } = useScanContext();
  const state = getState(mode);
  const ids = nodeIds(mode);
  if (!ids.length) return 0;
  if (state.scanComplete) return 100;
  return Math.round((state.doneNodes.filter((d) => ids.includes(d)).length / ids.length) * 100);
}
