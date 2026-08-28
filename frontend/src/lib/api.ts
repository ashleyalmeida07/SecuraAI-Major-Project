/**
 * API client for communicating with the AuthTrack FastAPI backend.
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
  summary: Record<string, number>;
}

export interface HeaderFinding {
  url: string;
  header_name: string;
  expected: string;
  actual: string | null;
  severity: string;
  description: string;
}

export interface HeaderAuditReport {
  target_url: string;
  total_findings: number;
  findings: HeaderFinding[];
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
  findings: InjectionFinding[];
  discarded_findings?: InjectionFinding[];
  type_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
  summary: string;
  scan_timestamp: string;
}

export interface InjectionScanResponse {
  status: string;
  injection_report: InjectionReport;
  errors: string[];
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
