/**
 * Definitions for the four scan flows, each of which has its own tab.
 *
 * The scan pages were previously one page with a radio group; splitting them into
 * a tab per flow means the metadata that used to be inlined in that page — what
 * the flow does, what input it takes, which backend graph nodes it runs — has to
 * live somewhere both the tab bar and the individual pages can read. That is this
 * file.
 */

import type { ElementType } from "react";
import {
  Activity, Bug, Boxes, Brain, ClipboardCheck, Code, Database, FileSearch,
  FileText, GitMerge, Globe, KeyRound, Map, Radio, Route, Scale, ShieldCheck,
  Wrench, Zap,
} from "lucide-react";
import type { PipelineNode, PipelineStage } from "@/components/ui/scan-pipeline";
import { TOOL_META } from "@/lib/static-analysis";

export type ScanMode = "static" | "recon" | "full" | "injection";

/** A sequential node in one of the URL-driven flows. */
export interface FlowNode {
  /** Matches the backend graph node name exactly. */
  id: string;
  name: string;
  tool: string;
  icon: ElementType;
  description: string;
  activeDesc: string;
}

export interface ScanFlowMeta {
  mode: ScanMode;
  /** Route segment under /scan. */
  slug: string;
  /** Tab label. */
  short: string;
  /** Page heading. */
  label: string;
  icon: ElementType;
  /** Sidebar nav id in dashboard-layout. */
  navId: string;
  badge?: string;
  badgeClass?: string;
  /** Whether the flow takes a local path or a target URL. */
  input: "path" | "url";
  tagline: string;
  /** One paragraph shown under the page heading. */
  description: string;
  bullets: string[];
  accent: string;
}

export const SCAN_FLOWS: ScanFlowMeta[] = [
  {
    mode: "static",
    slug: "static",
    short: "Static Analysis",
    label: "Static Code Analysis",
    icon: Code,
    navId: "scan-static",
    badge: "SAST",
    badgeClass: "bg-violet-500/10 text-violet-400 border-violet-500/20",
    input: "path",
    tagline: "Five scanners over your source code, in parallel",
    description:
      "Points five independent engines at a local repository or a public GitHub repo at " +
      "once — pattern rules, dependency advisories, secret detection and full taint " +
      "analysis — then merges their findings, grounds each one in similar known-vulnerable " +
      "code, and has an LLM confirm or rule it out before writing a patch. Run it from your " +
      "terminal with the secura npm CLI, or in the form below.",
    bullets: [
      "Runs from your terminal via the secura npm CLI (npm i -g @authtrack/secura)",
      "Scan a local path or paste a public GitHub repo URL",
      "Semgrep, Bearer, OSV-Scanner, Gitleaks and CodeQL run concurrently",
      "Cross-tool deduplication with multi-tool corroboration",
      "RAG-grounded triage, plus a remediation diff for every confirmed finding",
    ],
    accent: "#a78bfa",
  },
  {
    mode: "recon",
    slug: "recon",
    short: "Recon",
    label: "Recon & Surface Mapping",
    icon: Globe,
    navId: "scan-recon",
    input: "url",
    tagline: "Map the attack surface before testing it",
    description:
      "Renders the target in a real headless browser (Playwright), so it works on modern " +
      "JavaScript apps and SPAs — following links, extracting forms and parameters, and " +
      "capturing the live API/XHR calls each page fires at runtime. An LLM then classifies " +
      "every endpoint it found. This is the flow the header audit and injection tests " +
      "consume as their input.",
    bullets: [
      "Renders JavaScript in a headless browser — works on SPAs and modern sites",
      "Captures live XHR/fetch API calls, forms and parameters",
      "Follows links to a configurable depth",
      "LLM tags each endpoint (auth page, API, static asset…)",
    ],
    accent: "#22d3ee",
  },
  {
    mode: "full",
    slug: "full",
    short: "Header Audit",
    label: "Full Scan — Recon + Header Audit",
    icon: ShieldCheck,
    navId: "scan-headers",
    badge: "recommended",
    input: "url",
    tagline: "Surface map plus a security-header and cookie audit",
    description:
      "Runs recon first, then fetches every discovered endpoint's response headers and " +
      "checks them against ten security rules. An LLM scores each violation in context — " +
      "a missing header on a login page is not the same risk as on a static image.",
    bullets: [
      "Everything the recon flow produces",
      "CSP, HSTS, X-Frame-Options, cookie flags and more",
      "Context-aware severity scoring",
      "Executive summary written for the report",
    ],
    accent: "#34d399",
  },
  {
    mode: "injection",
    slug: "injection",
    short: "Injection Test",
    label: "Injection Testing",
    icon: Zap,
    navId: "scan-injection",
    badge: "active testing",
    badgeClass: "bg-red-500/10 text-red-400 border-red-500/20",
    input: "url",
    tagline: "Actively probe parameters for injection flaws",
    description:
      "The only flow that sends attack traffic. It maps the surface, generates payloads " +
      "per injection class, replays each request alongside a clean baseline, and has an " +
      "LLM read the response differences to decide whether an attack actually landed.",
    bullets: [
      "SQLi, XSS, command injection and path traversal",
      "Baseline vs payload response comparison",
      "LLM confirms or discards each anomaly",
      "Only run this against systems you are authorised to test",
    ],
    accent: "#f87171",
  },
];

export const flowByMode = (mode: ScanMode): ScanFlowMeta =>
  SCAN_FLOWS.find((flow) => flow.mode === mode)!;

export const flowBySlug = (slug: string): ScanFlowMeta | undefined =>
  SCAN_FLOWS.find((flow) => flow.slug === slug);

// ── Node definitions for the URL-driven flows ────────────────────────────────

const CRAWLER: FlowNode = {
  id: "crawler", icon: Bug, name: "Crawler Node", tool: "Playwright (headless Chromium)",
  description: "Renders each page in a real browser, then captures links, forms and the live API/XHR calls it fires",
  activeDesc: "Rendering pages in a headless browser and capturing network calls...",
};

const CLASSIFIER: FlowNode = {
  id: "classifier", icon: Brain, name: "Classifier Node", tool: "LLM",
  description: "Classifies each endpoint by type using AI",
  activeDesc: "Sending endpoints to AI for classification...",
};

const SURFACE_REPORT: FlowNode = {
  id: "surface_report", icon: Map, name: "Surface Report Node", tool: "Pure logic",
  description: "Assembles the structured attack-surface report",
  activeDesc: "Building attack surface map...",
};

export const RECON_NODES: FlowNode[] = [CRAWLER, CLASSIFIER, SURFACE_REPORT];

export const FULL_NODES: FlowNode[] = [
  ...RECON_NODES,
  { id: "header_fetcher", icon: Radio, name: "Header Fetcher Node", tool: "httpx",
    description: "Fetches HTTP headers and cookies from each endpoint",
    activeDesc: "Fetching response headers and cookies..." },
  { id: "rule_checker", icon: ClipboardCheck, name: "Rule Checker Node", tool: "Rules engine",
    description: "Validates headers against 10 security rules",
    activeDesc: "Running security rules: HSTS, CSP, X-Frame-Options..." },
  { id: "severity_scorer", icon: Scale, name: "Severity Scorer Node", tool: "LLM",
    description: "AI assigns severity ratings and writes the executive summary",
    activeDesc: "AI scoring severities and writing summary..." },
];

export const INJECTION_NODES: FlowNode[] = [
  ...RECON_NODES,
  { id: "payload_generator", icon: Zap, name: "Payload Generator", tool: "Payload library",
    description: "Generates SQLi, XSS and injection payloads per endpoint",
    activeDesc: "Generating attack payloads for discovered endpoints..." },
  { id: "injector", icon: Activity, name: "Injector Node", tool: "httpx",
    description: "Sends baseline + payload requests and records differences",
    activeDesc: "Sending baseline and injected requests..." },
  { id: "response_analyzer", icon: Brain, name: "Response Analyzer", tool: "LLM",
    description: "AI compares responses to confirm or discard injection flaws",
    activeDesc: "LLM analyzing response differences..." },
  { id: "report_builder", icon: FileText, name: "Report Builder", tool: "LLM + logic",
    description: "Assembles the final injection report with recommendations",
    activeDesc: "Building injection report with executive summary..." },
];

export const FLOW_NODES: Record<Exclude<ScanMode, "static">, FlowNode[]> = {
  recon: RECON_NODES,
  full: FULL_NODES,
  injection: INJECTION_NODES,
};

// ── Stage groupings for the URL-driven flows ─────────────────────────────────

/** A sequential FlowNode becomes a single-event pipeline node (id == backend node). */
function toPipelineNode(node: FlowNode, accent: string): PipelineNode {
  return {
    id: node.id,
    name: node.name,
    tool: node.tool,
    icon: node.icon,
    description: node.description,
    activeDesc: node.activeDesc,
    events: [node.id],
    accent,
  };
}

const RECON_STAGE = (accent: string): PipelineStage => ({
  id: "recon",
  title: "Recon & Surface Mapping",
  caption: "Crawl the target, then classify every endpoint it exposes.",
  nodes: RECON_NODES.map((n) => toPipelineNode(n, accent)),
});

/**
 * The URL flows as pipeline stages, so the four tabs share one renderer. Recon is
 * a single stage; the full and injection flows add a second stage for the work
 * that consumes recon's endpoint list.
 */
export const URL_FLOW_STAGES: Record<Exclude<ScanMode, "static">, PipelineStage[]> = {
  recon: [RECON_STAGE(flowByMode("recon").accent)],
  full: [
    RECON_STAGE(flowByMode("full").accent),
    {
      id: "audit",
      title: "Security Header Audit",
      caption: "Fetch each endpoint's headers, check ten rules, then score them in context.",
      nodes: FULL_NODES.slice(RECON_NODES.length).map((n) =>
        toPipelineNode(n, flowByMode("full").accent),
      ),
    },
  ],
  injection: [
    RECON_STAGE(flowByMode("injection").accent),
    {
      id: "inject",
      title: "Injection Testing",
      caption: "Generate payloads, replay them against a baseline, then confirm what landed.",
      nodes: INJECTION_NODES.slice(RECON_NODES.length).map((n) =>
        toPipelineNode(n, flowByMode("injection").accent),
      ),
    },
  ],
};

/** Pipeline stages for any flow — static has its own hand-authored stages. */
export function stagesForMode(mode: ScanMode): PipelineStage[] {
  return mode === "static" ? STATIC_STAGES : URL_FLOW_STAGES[mode];
}

// ── Stage definitions for the static analysis flow ───────────────────────────

/**
 * The Static Analysis flow as pipeline stages: a five-tool parallel fan-out, a
 * merge barrier, the RAG-triage loop, then remediation + reporting. Pipeline node
 * ids equal the backend graph node names (confirm/discard fold onto triage), and
 * the five scanner accents come from TOOL_META so the CLI, the tool table and
 * these cards all colour the same engine the same way.
 */
export const STATIC_STAGES: PipelineStage[] = [
  {
    id: "scan",
    title: "Parallel Security Scan",
    caption:
      "Five independent engines analyse the code at once — SAST, dependency, secrets and taint analysis.",
    parallel: true,
    nodes: [
      { id: "run_semgrep", name: "Semgrep", tool: "SAST", icon: FileSearch, accent: TOOL_META.semgrep.color,
        description: "Pattern-based rules across every language in the repo",
        activeDesc: "Running Semgrep rules across the repository...", events: ["run_semgrep"] },
      { id: "run_bearer", name: "Bearer", tool: "SAST + Privacy", icon: ShieldCheck, accent: TOOL_META.bearer.color,
        description: "Dataflow-aware rules with strong CWE/OWASP tagging",
        activeDesc: "Running Bearer dataflow rules...", events: ["run_bearer"] },
      { id: "run_osv_scanner", name: "OSV-Scanner", tool: "SCA", icon: Boxes, accent: TOOL_META["osv-scanner"].color,
        description: "Lockfile dependencies vs the OSV advisory database",
        activeDesc: "Matching dependencies against known advisories...", events: ["run_osv_scanner"] },
      { id: "run_gitleaks", name: "Gitleaks", tool: "Secrets", icon: KeyRound, accent: TOOL_META.gitleaks.color,
        description: "Hardcoded credentials and API keys (values redacted)",
        activeDesc: "Scanning for hardcoded secrets...", events: ["run_gitleaks"] },
      { id: "run_codeql", name: "CodeQL", tool: "Taint Analysis", icon: Route, accent: TOOL_META.codeql.color,
        description: "Full source → sink dataflow — proof of reachability",
        activeDesc: "Building CodeQL database and tracing taint paths...", events: ["run_codeql"] },
    ],
  },
  {
    id: "merge",
    title: "Merge & Deduplicate",
    caption:
      "Normalise all five tools into one schema; issues flagged by multiple tools are cross-confirmed.",
    nodes: [
      { id: "merge_findings", name: "Merge Findings", tool: "Fan-in Barrier", icon: GitMerge, accent: "#22d3ee",
        description: "Waits for all five scanners, then dedupes into one set",
        activeDesc: "Merging and deduplicating findings across all tools...", events: ["merge_findings"] },
    ],
  },
  {
    id: "triage",
    title: "RAG-Enriched Triage",
    caption:
      "Each finding is matched against known-vulnerable patterns, then an LLM confirms it or rules it out.",
    nodes: [
      { id: "retrieve_context", name: "Context Retrieval", tool: "Upstash Vector RAG", icon: Database, accent: "#a78bfa",
        description: "Pulls similar known-vulnerable code for each finding",
        activeDesc: "Querying the vector DB for similar patterns...", events: ["retrieve_context"] },
      { id: "triage", name: "AI Triage", tool: "LLM", icon: Scale, accent: "#f59e0b",
        description: "Confirms real issues, rules out false positives",
        activeDesc: "LLM triaging each finding — a taint path biases toward confirmed...",
        events: ["triage", "confirm_finding", "discard_finding"] },
    ],
  },
  {
    id: "report",
    title: "Remediate & Report",
    caption: "Generate grounded fixes for confirmed issues, then assemble the final report.",
    nodes: [
      { id: "fix_generator", name: "Fix Generator", tool: "LLM + Safe Patterns", icon: Wrench, accent: "#10b981",
        description: "Framework-specific diffs grounded in verified safe code",
        activeDesc: "Generating secure code fixes...", events: ["fix_generator"] },
      { id: "report_builder", name: "Report Builder", tool: "Aggregation", icon: FileText, accent: "#60a5fa",
        description: "Assembles per-tool stats, taint evidence and fixes",
        activeDesc: "Building the final static analysis report...", events: ["report_builder"] },
    ],
  },
];

/** Every pipeline node id, in execution order. */
export const STATIC_NODE_IDS = STATIC_STAGES.flatMap((stage) =>
  stage.nodes.map((node) => node.id),
);

const STATIC_SCANNER_IDS = STATIC_STAGES[0].nodes.map((node) => node.id);

/**
 * Map a backend graph node name to the pipeline node id it drives. The triage
 * loop's confirm/discard branches fold onto the single "triage" card, and
 * `dispatch` has no card of its own — it only kicks off the fan-out.
 */
export function staticNodeId(backendNode: string): string {
  if (backendNode === "dispatch") return "";
  if (backendNode === "confirm_finding" || backendNode === "discard_finding") return "triage";
  return backendNode;
}

export { STATIC_SCANNER_IDS };
