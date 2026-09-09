"use client";

/**
 * Drives one scan run and exposes everything the UI needs to render it.
 *
 * All four flows stream the same SSE envelope, so the streaming, per-node status
 * bookkeeping and history persistence are identical between them — only the node
 * layout and the parsers differ. Keeping that here means each scan tab is just a
 * form plus a live view.
 *
 * Node statuses are *derived* rather than stored. The backend only tells us when
 * a node finishes; "active" is a function of what has finished so far, and
 * computing it on read avoids a class of bug where a fast node's completion event
 * arrives before we marked it active and it renders as still running.
 */

import { useCallback, useMemo, useRef, useState } from "react";
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

export interface StartOptions {
  /** Target URL, or a local repository path for the static flow. */
  target: string;
  maxDepth?: number;
  maxPages?: number;
  includeCodeql?: boolean;
  maxTriage?: number;
}

const now = () =>
  new Date().toLocaleTimeString([], {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

/**
 * Static-flow node statuses.
 *
 * The five scanners share one superstep and finish out of order, so they go
 * active together the moment `dispatch` lands. The triage loop has no terminal
 * event of its own — it simply stops looping — so it is held active until the
 * fix generator reports, and a report with no findings at all back-fills every
 * skipped stage as done.
 */
function deriveStaticStatuses(done: Set<string>, running: boolean): Record<string, NodeStatus> {
  const statuses: Record<string, NodeStatus> = {};
  const finished = done.has("report_builder");
  if (finished) {
    STATIC_NODE_IDS.forEach((id) => (statuses[id] = "done"));
    return statuses;
  }

  const active = (condition: boolean): NodeStatus =>
    condition && running ? "active" : "idle";

  const scannersDone = STATIC_SCANNER_IDS.every((id) => done.has(id));

  STATIC_SCANNER_IDS.forEach((id) => {
    statuses[id] = done.has(id) ? "done" : active(done.has("dispatch"));
  });
  statuses.merge_findings = done.has("merge_findings") ? "done" : active(scannersDone);
  statuses.retrieve_context = done.has("retrieve_context")
    ? "done"
    : active(done.has("merge_findings"));
  statuses.triage = done.has("fix_generator") ? "done" : active(done.has("retrieve_context"));
  statuses.fix_generator = done.has("fix_generator") ? "done" : active(done.has("triage"));
  statuses.report_builder = active(done.has("fix_generator"));

  return statuses;
}

/** Sequential-flow node statuses: node n is active once every earlier node is done. */
function deriveFlowStatuses(
  nodeIds: string[],
  done: Set<string>,
  running: boolean,
): Record<string, NodeStatus> {
  const statuses: Record<string, NodeStatus> = {};
  let reachedPending = false;
  nodeIds.forEach((id) => {
    if (done.has(id)) {
      statuses[id] = "done";
      return;
    }
    statuses[id] = !reachedPending && running ? "active" : "idle";
    reachedPending = true;
  });
  return statuses;
}

export function useScanRun(mode: ScanMode) {
  const [scanning, setScanning] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activity, setActivity] = useState("");
  const [doneNodes, setDoneNodes] = useState<string[]>([]);
  const [results, setResults] = useState<Record<string, NodeResult>>({});

  // Raw backend state per node, kept for reconstructing the final report payload.
  const rawStates = useRef<Record<string, any>>({});
  const triageAcc = useRef<TriageAcc>({ confirmed: 0, discarded: 0, done: 0, total: 0 });

  const nodeIds = useMemo(
    () => (mode === "static" ? STATIC_NODE_IDS : FLOW_NODES[mode].map((n) => n.id)),
    [mode],
  );

  const statuses = useMemo(() => {
    const done = new Set(doneNodes);
    const running = scanning || scanComplete;
    return mode === "static"
      ? deriveStaticStatuses(done, running)
      : deriveFlowStatuses(nodeIds, done, running);
  }, [doneNodes, mode, nodeIds, scanning, scanComplete]);

  const progressPct = useMemo(() => {
    if (!scanning && !scanComplete) return 0;
    const total = nodeIds.length;
    const complete = nodeIds.filter((id) => statuses[id] === "done").length;
    return total ? Math.round((complete / total) * 100) : 0;
  }, [nodeIds, statuses, scanning, scanComplete]);

  // The headline report object, reconstructed from the raw per-node states.
  // `rawStates` is a ref, so this recomputes as nodes finish (doneNodes) and on
  // completion — the two moments the underlying states actually change.
  const report = useMemo(
    () => extractReport(mode, rawStates.current),
    [mode, doneNodes, scanComplete],
  );

  const reset = useCallback(() => {
    setScanning(false);
    setScanComplete(false);
    setError(null);
    setActivity("");
    setDoneNodes([]);
    setResults({});
    rawStates.current = {};
    triageAcc.current = { confirmed: 0, discarded: 0, done: 0, total: 0 };
  }, []);

  const start = useCallback(
    async (options: StartOptions) => {
      reset();
      setScanning(true);

      const markDone = (id: string) =>
        setDoneNodes((prev) => (prev.includes(id) ? prev : [...prev, id]));

      const handleEvent = (data: any) => {
        if (data.event === "start" || data.event === "handoff" || data.event === "complete") {
          setActivity(data.message);
          return;
        }
        if (data.event === "error") {
          setError(data.message);
          setActivity(`Error: ${data.message}`);
          return;
        }
        if (data.event !== "node_update") return;

        const backendNode: string = data.node;
        rawStates.current[backendNode] = data.state;

        if (mode !== "static") {
          markDone(backendNode);
          const parsed = parseFlowNode(backendNode, data.state);
          setResults((prev) => ({ ...prev, [backendNode]: { ...parsed, timestamp: now() } }));
          setActivity(`${backendNode} — ${parsed.summary ?? "completed"}`);
          return;
        }

        // ── static flow ──
        // `dispatch` has no card; it only signals that the fan-out has begun.
        markDone(backendNode === "dispatch" ? "dispatch" : staticNodeId(backendNode));

        const acc = triageAcc.current;
        if (backendNode === "triage" && data.state?.triage_progress) {
          acc.total = data.state.triage_progress.total ?? acc.total;
          acc.done = data.state.triage_progress.done ?? acc.done;
        } else if (backendNode === "confirm_finding") {
          acc.confirmed += (data.state?.triaged_findings || []).length || 1;
        } else if (backendNode === "discard_finding") {
          acc.discarded += (data.state?.false_positives || []).length || 1;
        }

        const pipelineId = staticNodeId(backendNode);
        if (!pipelineId) {
          setActivity(
            `Target resolved (CodeQL language: ${data.state?.codeql_language || "auto"}) — ` +
              "fanning out to 5 scanners",
          );
          return;
        }

        // The triage card needs the finding under review, which lives on the
        // `triage` update rather than on the confirm/discard branch that follows.
        const stateForCard =
          pipelineId === "triage"
            ? { ...(rawStates.current.triage || {}), ...data.state }
            : data.state;

        const parsed = parseStaticNode(pipelineId, stateForCard, acc);
        setResults((prev) => ({ ...prev, [pipelineId]: { ...parsed, timestamp: now() } }));
        setActivity(`${pipelineId} — ${parsed.summary ?? "completed"}`);
      };

      try {
        if (mode === "static") {
          await scanStaticStream(
            {
              target_path: options.target,
              include_codeql: options.includeCodeql ?? true,
              max_triage: options.maxTriage ?? 25,
            },
            handleEvent,
          );
        } else {
          const request = {
            url: options.target,
            max_depth: options.maxDepth ?? 2,
            max_pages: options.maxPages ?? 15,
          };
          if (mode === "recon") await scanReconStream(request, handleEvent);
          else if (mode === "injection") await scanInjectionStream(request, handleEvent);
          else await scanFullStream(request, handleEvent);
        }

        setDoneNodes(mode === "static" ? [...nodeIds, "dispatch"] : [...nodeIds]);
        setScanComplete(true);
        setActivity("Scan complete — all nodes finished.");
        persistRun(mode, options.target, rawStates.current);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Scan failed. Is the backend running?");
      } finally {
        setScanning(false);
      }
    },
    [mode, nodeIds, reset],
  );

  return {
    scanning,
    scanComplete,
    error,
    activity,
    statuses,
    results,
    progressPct,
    report,
    start,
    reset,
  };
}

/** Pull the flow's headline report object out of the raw per-node states. */
function extractReport(mode: ScanMode, states: Record<string, any>) {
  if (mode === "static") return states.report_builder?.static_report ?? null;
  if (mode === "injection") return states.report_builder?.injection_report ?? null;
  if (mode === "full") return states.severity_scorer?.audit_report ?? null;
  return states.surface_report?.surface_report ?? null;
}

/** Write the finished run into localStorage so the reports page can read it back. */
function persistRun(mode: ScanMode, target: string, states: Record<string, any>) {
  const surface = states.surface_report?.surface_report || {};

  let data: any;
  if (mode === "recon") {
    data = { status: "success", surface_report: surface, errors: [] };
  } else if (mode === "injection") {
    data = {
      status: "success",
      surface_report: surface,
      injection_report: states.report_builder?.injection_report || null,
      errors: [],
    };
  } else if (mode === "static") {
    const report = states.report_builder?.static_report || null;
    data = { status: "success", static_analysis_report: report, errors: report?.errors || [] };
  } else {
    data = {
      status: "success",
      surface_report: surface,
      header_audit_report: states.severity_scorer?.audit_report || null,
      errors: [],
    };
  }

  try {
    const record = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      url: target,
      mode,
      data,
    };
    const raw = localStorage.getItem("authtrack_scan_history");
    const history = raw ? JSON.parse(raw) : [];
    history.unshift(record);
    localStorage.setItem("authtrack_scan_history", JSON.stringify(history));

    sessionStorage.setItem("authtrack_scan_result", JSON.stringify(data));
    sessionStorage.setItem("authtrack_scan_mode", mode);
    sessionStorage.setItem("authtrack_scan_url", target);
  } catch {
    // A full or unavailable storage quota must not fail a completed scan.
  }
}
