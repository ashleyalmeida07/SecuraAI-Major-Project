"use client";

/**
 * Stage-based pipeline view for a running scan.
 *
 * The static analysis flow fans out to five scanners at once, so a flat vertical
 * timeline misrepresents it — the five tools are not sequential steps and do not
 * finish in declaration order. This component groups nodes into stages and
 * renders a `parallel` stage as a grid with an explicit "all at once" marker,
 * so what the graph actually does is what the user sees.
 */

import React, { useState } from "react";
import {
  ChevronDown, ChevronRight, Loader2, Check, X, GitMerge, Zap,
} from "lucide-react";

export type NodeStatus = "idle" | "active" | "done" | "error";
export type MetricTone = "neutral" | "danger" | "warn" | "success" | "info";

export interface PipelineNode {
  id: string;
  name: string;
  /** The underlying tool or technique, shown as a chip. */
  tool: string;
  icon: React.ElementType;
  /** Shown before the node runs. */
  description: string;
  /** Shown while the node is running. */
  activeDesc: string;
  /** Backend graph node names that drive this UI node. Several map to one when
   *  the graph loops (triage → confirm/discard → triage). */
  events: string[];
  /** Accent color for the node's icon ring — used for the scanner cards. */
  accent?: string;
}

export interface PipelineStage {
  id: string;
  /** Short stage name, e.g. "Parallel Scan". */
  title: string;
  /** One line explaining what the stage accomplishes. */
  caption: string;
  /** True when every node in the stage runs concurrently. */
  parallel?: boolean;
  nodes: PipelineNode[];
}

export interface NodeMetric {
  label: string;
  value: string | number;
  tone?: MetricTone;
}

export interface NodeResult {
  summary?: string;
  metrics?: NodeMetric[];
  detail?: React.ReactNode;
  /** What this node hands to the next one. */
  handoff?: string;
  timestamp?: string;
  /** Live progress for looping nodes. */
  progress?: { done: number; total: number };
}

const TONE_CLASSES: Record<MetricTone, string> = {
  neutral: "bg-secondary/60 text-foreground border-border",
  danger: "bg-red-500/10 text-red-400 border-red-500/25",
  warn: "bg-amber-500/10 text-amber-400 border-amber-500/25",
  success: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
  info: "bg-cyan-500/10 text-cyan-400 border-cyan-500/25",
};

function MetricChip({ metric }: { metric: NodeMetric }) {
  return (
    <div
      className={`flex items-baseline gap-1.5 rounded-md border px-2 py-1 ${
        TONE_CLASSES[metric.tone || "neutral"]
      }`}
    >
      <span className="text-[13px] font-bold leading-none tabular-nums">{metric.value}</span>
      <span className="text-[10px] uppercase tracking-wider opacity-70">{metric.label}</span>
    </div>
  );
}

function StatusDot({ status, icon: Icon, accent }: { status: NodeStatus; icon: React.ElementType; accent?: string }) {
  const base = "flex h-7 w-7 shrink-0 items-center justify-center rounded-full border-2 transition-colors";
  if (status === "done") {
    return (
      <div className={`${base} border-emerald-500 bg-emerald-500/10 text-emerald-400`}>
        <Check className="h-3.5 w-3.5" />
      </div>
    );
  }
  if (status === "error") {
    return (
      <div className={`${base} border-rose-500 bg-rose-500/10 text-rose-400`}>
        <X className="h-3.5 w-3.5" />
      </div>
    );
  }
  if (status === "active") {
    return (
      <div
        className={`${base} animate-pulse bg-blue-500/10`}
        style={{ borderColor: accent || "#3b82f6", color: accent || "#60a5fa" }}
      >
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      </div>
    );
  }
  return (
    <div className={`${base} border-muted-foreground/25 text-muted-foreground/40`}>
      <Icon className="h-3.5 w-3.5" />
    </div>
  );
}

function NodeCard({
  node,
  status,
  result,
  compact,
}: {
  node: PipelineNode;
  status: NodeStatus;
  result?: NodeResult;
  compact?: boolean;
}) {
  const hasDetail = Boolean(result?.detail);
  const [expanded, setExpanded] = useState(false);
  // Auto-open the newest finished node so results surface without a click,
  // but let an explicit toggle win afterwards.
  const [touched, setTouched] = useState(false);
  const open = touched ? expanded : hasDetail && (status === "done" || status === "error");

  const border =
    status === "done"
      ? "border-emerald-500/25 bg-emerald-500/[0.03]"
      : status === "active"
      ? "border-blue-500/40 bg-blue-500/[0.04] shadow-sm shadow-blue-500/10"
      : status === "error"
      ? "border-rose-500/30 bg-rose-500/[0.04]"
      : "border-border/40 bg-background/40";

  return (
    <div className={`rounded-lg border transition-all duration-300 ${border} ${status === "idle" ? "opacity-60" : ""}`}>
      <button
        type="button"
        className={`flex w-full items-start gap-3 p-3 text-left ${hasDetail ? "cursor-pointer" : "cursor-default"}`}
        onClick={() => {
          if (!hasDetail) return;
          setTouched(true);
          setExpanded(!open);
        }}
      >
        <StatusDot status={status} icon={node.icon} accent={node.accent} />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold text-foreground">{node.name}</span>
            <span
              className="rounded border px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wider"
              style={{
                borderColor: `${node.accent || "#64748b"}40`,
                color: node.accent || "#94a3b8",
                background: `${node.accent || "#64748b"}12`,
              }}
            >
              {node.tool}
            </span>
            {result?.progress && status === "active" && (
              <span className="text-[10px] font-mono tabular-nums text-blue-400">
                {result.progress.done}/{result.progress.total}
              </span>
            )}
          </div>

          <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
            {status === "active"
              ? node.activeDesc
              : result?.summary
              ? result.summary
              : node.description}
          </p>

          {result?.metrics && result.metrics.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {result.metrics.map((metric) => (
                <MetricChip key={metric.label} metric={metric} />
              ))}
            </div>
          )}

          {status === "active" && result?.progress && result.progress.total > 0 && (
            <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full bg-blue-500 transition-all duration-500"
                style={{ width: `${Math.round((result.progress.done / result.progress.total) * 100)}%` }}
              />
            </div>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {result?.timestamp && (
            <span className="hidden font-mono text-[10px] tabular-nums text-muted-foreground/60 sm:inline">
              {result.timestamp}
            </span>
          )}
          {hasDetail && (
            <span className="text-muted-foreground/40">
              {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </span>
          )}
        </div>
      </button>

      {open && result?.detail && (
        <div className="border-t border-border/40 px-3 pb-3 pt-2.5">{result.detail}</div>
      )}

      {!compact && status === "done" && result?.handoff && (
        <div className="flex items-center gap-1.5 border-t border-border/30 px-3 py-2 font-mono text-[10px] text-primary/70">
          <ChevronRight className="h-3 w-3" />
          {result.handoff}
        </div>
      )}
    </div>
  );
}

export interface ScanPipelineProps {
  stages: PipelineStage[];
  statuses: Record<string, NodeStatus>;
  results: Record<string, NodeResult>;
}

export function ScanPipeline({ stages, statuses, results }: ScanPipelineProps) {
  return (
    <div className="flex flex-col">
      {stages.map((stage, stageIndex) => {
        const nodeStatuses = stage.nodes.map((n) => statuses[n.id] || "idle");
        const doneCount = nodeStatuses.filter((s) => s === "done").length;
        const stageActive = nodeStatuses.some((s) => s === "active");
        const stageDone = doneCount === stage.nodes.length;
        const isLast = stageIndex === stages.length - 1;

        return (
          <div key={stage.id} className="relative">
            {/* Stage header */}
            <div className="mb-3 flex items-center gap-3">
              <div
                className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md border text-[11px] font-bold tabular-nums transition-colors ${
                  stageDone
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                    : stageActive
                    ? "border-blue-500/50 bg-blue-500/10 text-blue-400"
                    : "border-border bg-secondary/50 text-muted-foreground"
                }`}
              >
                {stageIndex + 1}
              </div>

              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h4 className="text-[13px] font-semibold tracking-tight text-foreground">{stage.title}</h4>
                  {stage.parallel && (
                    <span className="flex items-center gap-1 rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-violet-400">
                      <Zap className="h-2.5 w-2.5" />
                      {stage.nodes.length} in parallel
                    </span>
                  )}
                  {stage.nodes.length > 1 && (
                    <span className="font-mono text-[10px] tabular-nums text-muted-foreground/70">
                      {doneCount}/{stage.nodes.length}
                    </span>
                  )}
                </div>
                <p className="text-[11px] leading-snug text-muted-foreground">{stage.caption}</p>
              </div>
            </div>

            {/* Stage nodes */}
            <div
              className={
                stage.parallel
                  ? "ml-9 grid grid-cols-1 gap-2 md:grid-cols-2"
                  : "ml-9 flex flex-col gap-2"
              }
            >
              {stage.nodes.map((node, i) => (
                <NodeCard
                  key={node.id}
                  node={node}
                  status={nodeStatuses[i]}
                  result={results[node.id]}
                  compact={stage.parallel}
                />
              ))}
            </div>

            {/* Connector into the next stage */}
            {!isLast && (
              <div className="ml-9 flex items-center gap-2 py-3 text-[10px] text-muted-foreground/60">
                <div className="h-4 w-px bg-border/70" />
                {stage.parallel ? (
                  <span className="flex items-center gap-1.5 font-mono">
                    <GitMerge className="h-3 w-3" />
                    all {stage.nodes.length} results converge on the next stage
                  </span>
                ) : (
                  <span className="font-mono">↓</span>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default ScanPipeline;
