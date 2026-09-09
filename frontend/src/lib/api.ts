/**
 * API client for communicating with the SecuraAI FastAPI backend.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export interface ScanRequest {
  url: string;
  max_depth?: number;
  max_pages?: number;
}

export interface Endpoint {
  url: string;
  method: string;
  endpoint_type: string;
  status_code: number;
  content_type?: string;
  parameters?: string[];
  technology?: string[];
  is_interesting?: boolean;
  response_size?: number;
  response_time?: number;
  form_inputs?: string[];
}

export interface SurfaceReport {
  target_url: string;
  total_endpoints: number;
  endpoints: Endpoint[];
  scan_timestamp: string;
  /** LLM-written executive summary of the attack surface (prose, not a map). */
  summary: string;
}

/** One checklist item evaluated for one endpoint. */
export interface HeaderCheckResult {
  url: string;
  endpoint_type: string;
  /** header | cookie | cors */
  category: string;
  header_name: string;
  expected: string;
  actual: string | null;
  /** pass | fail | missing */
  status: "pass" | "fail" | "missing";
  /** Only set for fail/missing items — passes are objectively correct. */
  severity: string | null;
  description: string;
  info?: string;
  weight?: number;
}

/** @deprecated Alias kept for older report records — same shape as a fail/missing check. */
export type HeaderFinding = HeaderCheckResult;

export interface HeaderAuditReport {
  target_url: string;
  endpoints_audited: number;
  /** Every check for every endpoint — pass, fail, and missing. */
  checklist: HeaderCheckResult[];
  /** The correctly-configured subset. */
  passes: HeaderCheckResult[];
  /** The fail/missing subset (LLM-scored). */
  findings: HeaderCheckResult[];
  total_findings: number;
  total_checks: number;
  /** Correctly configured, weighted checklist items — the numerator of the ratio. */
  configured_count: number;
  /** Total weighted checklist items — the denominator. */
  graded_total: number;
  severity_breakdown: Record<string, number>;
  summary: string;
  scan_timestamp: string;
}

export interface ReconResponse {
  status: string;
  surface_report: SurfaceReport;
  errors: string[];
}

export interface FullScanResponse {
  status: string;
  surface_report: SurfaceReport;
  header_audit_report: HeaderAuditReport;
  errors: string[];
}

export interface InjectionFinding {
  url: string;
  parameter: string;
  injection_type: string;
  payload_name: string;
  severity: string;
  evidence: string;
  description: string;
  recommendation: string;
  verdict?: string;
}

export interface InjectionReport {
  target_url: string;
  total_tested: number;
  total_confirmed: number;
  total_discarded: number;
  total_params_tested?: number;
  findings: InjectionFinding[];
  discarded_findings?: InjectionFinding[];
  tested_endpoints_detail?: TestedEndpointDetail[];
  type_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
  summary: string;
  scan_timestamp: string;
}

export interface TestedEndpointDetail {
  url: string;
  param_count: number;
  injection_types_tested: string[];
}

export interface InjectionScanResponse {
  status: string;
  injection_report: InjectionReport;
  errors: string[];
}

/** The five scanners in the static analysis fan-out stage. */
export type ToolSource = "semgrep" | "bearer" | "osv-scanner" | "gitleaks" | "codeql";

/** One hop in a CodeQL dataflow path (source → intermediate steps → sink). */
export interface TaintStep {
  step: number;
  role: "source" | "intermediate" | "sink";
  file: string;
  line: number;
  snippet: string;
  message: string;
}

/** A finding after normalization and cross-tool deduplication. */
export interface MergedFinding {
  tool_source: ToolSource;
  file: string;
  line: number;
  severity: string;
  rule_id: string;
  category: string;
  description: string;
  raw_snippet: string;
  /** CodeQL only — proof the vulnerability is actually reachable. */
  taint_path?: TaintStep[] | null;
  multi_tool_confirmed: boolean;
  confirmed_by: ToolSource[];
  cwe?: string[];
  owasp?: string[];
  package?: string | null;
  package_version?: string | null;
  fixed_versions?: string[];
  context?: RetrievedContext[];
  /** Set by the triage stage. */
  verdict?: "confirmed" | "false_positive";
  triage_reason?: string;
  triage_confidence?: string;
  final_severity?: string;
  db_id?: number | null;
}

/** A similar known-vulnerable pattern pulled from Upstash Vector. */
export interface RetrievedContext {
  vuln_id: string;
  pair_id?: string;
  score: number;
  similar_vulnerable_code: string;
  vuln_type?: string;
  framework?: string;
  language?: string;
  cwe?: string;
  owasp?: string;
}

export interface SafePattern {
  id: string;
  path: string;
  line: number;
  snippet: string;
  description: string;
  type: string;
}

export interface StaticFix {
  finding_id: number | null;
  file: string;
  line: number;
  category: string;
  severity: string;
  rule_id: string;
  tool_source: ToolSource;
  diff_text: string;
  explanation: string;
  /** Whether the fix was grounded in a paired safe example, a category match, or nothing. */
  grounded_in: "paired" | "category" | "none";
  safe_reference?: string | null;
}

/** Execution outcome for one scanner. */
export interface ToolRunStatus {
  tool: string;
  ok: boolean;
  finding_count: number;
  note: string;
  /** True when the tool was unavailable and representative sample data was used. */
  used_sample: boolean;
  duration_s: number;
}

/** Per-tool accounting: raw findings vs how many survived the merge. */
export interface ToolContribution {
  raw: number;
  after_merge: number;
  ran: boolean;
  used_sample: boolean;
  duration_s: number;
  note: string;
}

/** A confirmed CodeQL finding with its full taint chain, surfaced for the report. */
export interface TaintEvidence {
  rule_id: string;
  category: string;
  severity: string;
  file: string;
  line: number;
  source: TaintStep;
  sink: TaintStep;
  intermediate_steps: TaintStep[];
  taint_path: TaintStep[];
  step_count: number;
  /** "file:line → file:line → …" */
  chain: string;
  triage_reason: string;
}

/** The final output of the Static Analysis flow. */
export interface StaticAnalysisReport {
  /** The scanned target — a local path, or the repo URL for a cloned scan. */
  target_path: string;
  /** Set only when the scan targeted a remote Git repo (else ""). */
  source_repo?: string;
  scan_timestamp: string;
  codeql_language: string;

  findings_per_tool: Record<string, ToolContribution>;
  tool_status: Record<string, ToolRunStatus>;

  total_raw_findings: number;
  total_after_merge: number;
  duplicates_removed: number;
  multi_tool_confirmed_count: number;
  with_taint_path_count: number;

  confirmed_count: number;
  ruled_out_count: number;
  not_triaged_count: number;
  fixes_count: number;

  severity_breakdown: Record<string, number>;
  category_breakdown: Record<string, number>;
  merged_severity_breakdown?: Record<string, number>;
  merged_category_breakdown?: Record<string, number>;

  confirmed_findings: MergedFinding[];
  ruled_out_findings: MergedFinding[];
  safe_patterns: SafePattern[];
  fixes: StaticFix[];

  codeql_taint_evidence: TaintEvidence[];

  summary: string;
  errors: string[];
}

export interface StaticAnalysisResponse {
  status: string;
  static_analysis_report: StaticAnalysisReport;
  errors: string[];
}

/** Request body for the static analysis flow (scans a local code path). */
export interface StaticScanRequest {
  target_path: string;
  /** CodeQL is the slow tool — turn it off for a fast four-tool pass. */
  include_codeql?: boolean;
  /** "" → the backend auto-detects from the repo's manifests. */
  codeql_language?: string;
  /** Cap on how many merged findings get an LLM triage pass. */
  max_triage?: number;
}

/** Run Flow 1 only — Recon & Surface Mapping. */
export async function scanRecon(request: ScanRequest): Promise<ReconResponse> {
  const res = await fetch(`${API_BASE}/scan/recon`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!res.ok) throw new Error(`Recon scan failed: ${res.statusText}`);
  return res.json();
}

/** Run Flow 1 → Flow 2 chained — full scan pipeline. */
export async function scanFull(request: ScanRequest): Promise<FullScanResponse> {
  const res = await fetch(`${API_BASE}/scan/full`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!res.ok) throw new Error(`Full scan failed: ${res.statusText}`);
  return res.json();
}

/** 
 * Stream Flow 1 (Recon). 
 * onEvent is called with each parsed JSON chunk.
 */
export async function scanReconStream(
  request: ScanRequest, 
  onEvent: (data: any) => void
): Promise<void> {
  const res = await fetch(`${API_BASE}/scan/stream/recon`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!res.ok) throw new Error(`Stream failed: ${res.statusText}`);
  if (!res.body) throw new Error("No response body");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    buffer += decoder.decode(value, { stream: true });
    
    // Process SSE lines
    const lines = buffer.split('\n\n');
    buffer = lines.pop() || ""; // Keep the last incomplete chunk in the buffer

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const jsonStr = line.slice(6);
        if (jsonStr.trim()) {
          try {
            const data = JSON.parse(jsonStr);
            onEvent(data);
          } catch (e) {
            console.error("Failed to parse SSE JSON:", e, jsonStr);
          }
        }
      }
    }
  }
}

/** 
 * Stream Flow 1 -> Flow 2 chained (Full Scan). 
 */
export async function scanFullStream(
  request: ScanRequest, 
  onEvent: (data: any) => void
): Promise<void> {
  const res = await fetch(`${API_BASE}/scan/stream/full`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!res.ok) throw new Error(`Stream failed: ${res.statusText}`);
  if (!res.body) throw new Error("No response body");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    buffer += decoder.decode(value, { stream: true });
    
    // Process SSE lines
    const lines = buffer.split('\n\n');
    buffer = lines.pop() || ""; 

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const jsonStr = line.slice(6);
        if (jsonStr.trim()) {
          try {
            const data = JSON.parse(jsonStr);
            onEvent(data);
          } catch (e) {
            console.error("Failed to parse SSE JSON:", e, jsonStr);
          }
        }
      }
    }
  }
}

/**
 * Stream the Static Analysis flow (Semgrep → RAG → Triage → Fixes).
 * Scans a local repository/file path rather than a URL.
 */
export async function scanStaticStream(
  request: StaticScanRequest,
  onEvent: (data: any) => void
): Promise<void> {
  const res = await fetch(`${API_BASE}/scan/stream/static`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!res.ok) throw new Error(`Stream failed: ${res.statusText}`);
  if (!res.body) throw new Error("No response body");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n\n');
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const jsonStr = line.slice(6);
        if (jsonStr.trim()) {
          try {
            const data = JSON.parse(jsonStr);
            onEvent(data);
          } catch (e) {
            console.error("Failed to parse SSE JSON:", e, jsonStr);
          }
        }
      }
    }
  }
}

/**
 * Stream Flow 3: Injection Testing.
 */
export async function scanInjectionStream(
  request: { url: string; endpoints?: any[]; max_depth?: number; max_pages?: number },
  onEvent: (data: any) => void
): Promise<void> {
  const res = await fetch(`${API_BASE}/scan/stream/injection`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!res.ok) throw new Error(`Stream failed: ${res.statusText}`);
  if (!res.body) throw new Error("No response body");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n\n');
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const jsonStr = line.slice(6);
        if (jsonStr.trim()) {
          try {
            const data = JSON.parse(jsonStr);
            onEvent(data);
          } catch (e) {
            console.error("Failed to parse SSE JSON:", e, jsonStr);
          }
        }
      }
    }
  }
}
