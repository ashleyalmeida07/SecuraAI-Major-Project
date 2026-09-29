#!/usr/bin/env node
/**
 * secura-mcp — SecuraAI MCP server (stdio transport).
 *
 * Exposes four security-scanning tools to any MCP-capable AI editor
 * (Claude Code, Cursor, Continue, etc.).  The editor spawns this process
 * automatically; users never run it themselves.
 *
 * Tools exposed:
 *   run_static_scan   — SAST (Semgrep, Bearer, OSV-Scanner, Gitleaks, CodeQL)
 *   run_recon         — Surface mapping / endpoint discovery
 *   run_header_audit  — Security-header & cookie audit
 *   run_injection_scan — SQL / command / XSS injection testing
 *
 * Configuration (environment variables, all optional):
 *   SECURA_API    — Backend base URL  (default: https://securaai-major-project.onrender.com/api/v1)
 *   SECURA_TOKEN  — Bearer token for authenticated backends
 *
 * Usage in Claude Code / Cursor mcp config:
 *   {
 *     "mcpServers": {
 *       "secura": {
 *         "command": "secura-mcp",
 *         "env": {
 *           "SECURA_API": "http://localhost:8000/api/v1",
 *           "SECURA_TOKEN": "<your-jwt>"
 *         }
 *       }
 *     }
 *   }
 */

import { Server }            from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// ── Config ───────────────────────────────────────────────────────────────────

const DEFAULT_API = "https://securaai-major-project.onrender.com/api/v1";

function resolveConfig() {
  const api   = (process.env.SECURA_API   || DEFAULT_API).replace(/\/+$/, "");
  const token = process.env.SECURA_TOKEN  || "";
  return { api, token };
}

function authHeaders(token, extra = {}) {
  const h = { ...extra };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

// ── SSE streaming helpers ────────────────────────────────────────────────────

async function* readSse(res) {
  const decoder = new TextDecoder();
  const reader  = res.body.getReader();
  let buffer    = "";

  const emit = function* (frame) {
    for (const line of frame.split("\n")) {
      if (!line.startsWith("data:")) continue;
      const json = line.slice(line.indexOf(":") + 1).trim();
      if (!json) continue;
      try { yield JSON.parse(json); } catch { /* skip malformed */ }
    }
  };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() || "";
    for (const f of frames) yield* emit(f);
  }
  const tail = buffer.trim();
  if (tail) yield* emit(tail);
}

/**
 * Drain an SSE stream and collect the accumulated graph state.
 * Returns { finalState, scanId, error }.
 */
async function drainStream(url, token, headers, body) {
  let res;
  try {
    res = await fetch(url, {
      method:  "POST",
      headers: authHeaders(token, headers),
      body,
    });
  } catch (err) {
    throw new Error(`Cannot reach SecuraAI backend at ${url}: ${err.message}`);
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`Backend error ${res.status}: ${detail.slice(0, 400)}`);
  }

  const accumulated = {};
  let   scanId      = null;
  let   lastError   = null;

  for await (const evt of readSse(res)) {
    if (evt.event === "node_update" && evt.state) {
      Object.assign(accumulated, evt.state);
    }
    if (evt.event === "complete") {
      scanId = evt.scan_id ?? null;
    }
    if (evt.event === "error") {
      lastError = evt.message;
    }
  }

  return { finalState: accumulated, scanId, error: lastError };
}

// ── Tool implementations ─────────────────────────────────────────────────────

/** SAST — static analysis scan. */
async function runStaticScan(args) {
  const { api, token } = resolveConfig();
  const body = JSON.stringify({
    target_path:     args.target_path,
    include_codeql:  args.include_codeql  ?? true,
    codeql_language: args.codeql_language ?? "",
    max_triage:      args.max_triage      ?? 25,
  });

  const { finalState, scanId, error } = await drainStream(
    `${api}/scan/stream/static`, token,
    { "Content-Type": "application/json" }, body,
  );

  if (error) throw new Error(error);

  const report = finalState.static_report ?? {};
  return formatStaticReport(report, scanId);
}

/** Recon — surface mapping / endpoint discovery. */
async function runRecon(args) {
  const { api, token } = resolveConfig();
  const body = JSON.stringify({
    url:       args.url,
    max_depth: args.max_depth ?? 2,
    max_pages: args.max_pages ?? 30,
  });

  const { finalState, scanId, error } = await drainStream(
    `${api}/scan/stream/recon`, token,
    { "Content-Type": "application/json" }, body,
  );

  if (error) throw new Error(error);

  const report    = finalState.surface_report ?? {};
  const endpoints = finalState.classified_endpoints ?? report.endpoints ?? [];
  return formatReconReport(report, endpoints, scanId);
}

/** Header audit — security-header & cookie checks. */
async function runHeaderAudit(args) {
  const { api, token } = resolveConfig();
  const body = JSON.stringify({
    url:       args.url,
    max_depth: args.max_depth ?? 2,
    max_pages: args.max_pages ?? 30,
  });

  const { finalState, scanId, error } = await drainStream(
    `${api}/scan/stream/full`, token,
    { "Content-Type": "application/json" }, body,
  );

  if (error) throw new Error(error);

  const auditReport   = finalState.audit_report   ?? {};
  const surfaceReport = finalState.surface_report  ?? {};
  return formatHeaderReport(auditReport, surfaceReport, scanId);
}



// ── Formatters ───────────────────────────────────────────────────────────────

function formatStaticReport(report, scanId) {
  const lines = [
    "## SecuraAI Static Analysis Report",
    "",
    `**Target:** ${report.target ?? "unknown"}`,
    `**Scan ID:** ${scanId ?? "n/a"}`,
    `**Summary:** ${report.summary ?? "No summary available."}`,
    "",
    `| Metric | Count |`,
    `|--------|-------|`,
    `| Unique findings (after merge) | ${report.total_after_merge ?? 0} |`,
    `| Confirmed vulnerabilities | ${report.confirmed_count ?? 0} |`,
    `| Ruled out (false positives) | ${report.ruled_out_count ?? 0} |`,
    `| Fixes generated | ${report.fixes_count ?? 0} |`,
    `| With CodeQL taint path | ${report.with_taint_path_count ?? 0} |`,
    "",
  ];

  const confirmed = report.confirmed_findings ?? [];
  if (confirmed.length > 0) {
    lines.push("### Confirmed Vulnerabilities", "");
    confirmed.slice(0, 20).forEach((f, i) => {
      const sev      = (f.final_severity || f.severity || "info").toUpperCase();
      const evidence = f.taint_path      ? "taint path"
                     : f.multi_tool_confirmed ? "multi-tool"
                     : "single tool";
      lines.push(
        `**${i + 1}. [${sev}] ${f.category ?? f.rule_id}**`,
        `- File: \`${f.file}:${f.line}\``,
        `- Rule: \`${f.rule_id}\``,
        `- Evidence: ${evidence}`,
        f.triage_reason ? `- Reason: ${f.triage_reason}` : null,
        "",
      ).filter(Boolean);
    });
    if (confirmed.length > 20) lines.push(`_…and ${confirmed.length - 20} more_`, "");
  } else {
    lines.push("✅ No confirmed vulnerabilities found.", "");
  }

  return { content: [{ type: "text", text: lines.filter(l => l !== null).join("\n") }] };
}

function formatReconReport(report, endpoints, scanId) {
  const lines = [
    "## SecuraAI Recon Report",
    "",
    `**Target:** ${report.target_url ?? "unknown"}`,
    `**Scan ID:** ${scanId ?? "n/a"}`,
    `**Total Endpoints:** ${report.total_endpoints ?? endpoints.length}`,
    `**Scanned At:** ${report.scan_timestamp ?? new Date().toISOString()}`,
    "",
    report.summary ? `### Summary\n\n${report.summary}\n` : null,
    "### Endpoints Discovered",
    "",
    `| URL | Method | Type | Status |`,
    `|-----|--------|------|--------|`,
  ].filter(Boolean);

  endpoints.slice(0, 50).forEach(ep => {
    lines.push(
      `| \`${ep.url}\` | ${ep.method ?? "GET"} | ${ep.endpoint_type ?? "unknown"} | ${ep.status_code ?? "-"} |`
    );
  });

  if (endpoints.length > 50) lines.push(`\n_…and ${endpoints.length - 50} more endpoints_`);

  return { content: [{ type: "text", text: lines.join("\n") }] };
}

function formatHeaderReport(audit, surface, scanId) {
  const lines = [
    "## SecuraAI Header Audit Report",
    "",
    `**Target:** ${audit.target_url ?? surface.target_url ?? "unknown"}`,
    `**Scan ID:** ${scanId ?? "n/a"}`,
    `**Total Findings:** ${audit.total_findings ?? 0}`,
    "",
  ];

  const findings = audit.findings ?? [];
  if (findings.length > 0) {
    lines.push("### Findings", "");
    findings.slice(0, 30).forEach((f, i) => {
      const sev = (f.severity || "info").toUpperCase();
      lines.push(
        `**${i + 1}. [${sev}] ${f.header_name ?? f.category}**`,
        `- URL: \`${f.url}\``,
        `- Issue: ${f.issue ?? f.expected ?? ""}`,
        f.recommendation ? `- Fix: ${f.recommendation}` : null,
        "",
      ).filter(Boolean);
    });
  } else {
    lines.push("✅ No header misconfigurations found.", "");
  }

  return { content: [{ type: "text", text: lines.filter(l => l !== null).join("\n") }] };
}



// ── Tool definitions (shown to the AI) ───────────────────────────────────────

const TOOLS = [
  {
    name:        "run_static_scan",
    description: "Run SAST static analysis on a local code repository using Semgrep, Bearer, OSV-Scanner, Gitleaks and CodeQL. Returns confirmed vulnerabilities, false positives, and generated fixes.",
    inputSchema: {
      type: "object",
      properties: {
        target_path: {
          type:        "string",
          description: "Absolute or relative path to the local repository/folder to scan. Can also be a GitHub URL (https://github.com/owner/repo) or 'owner/repo' shorthand.",
        },
        include_codeql: {
          type:        "boolean",
          description: "Include CodeQL taint analysis (slower but finds deeper data-flow issues). Default: true.",
          default:     true,
        },
        codeql_language: {
          type:        "string",
          description: "CodeQL extractor language (javascript, python, java, go, ruby, csharp, cpp). Leave empty to auto-detect.",
          default:     "",
        },
        max_triage: {
          type:        "number",
          description: "Maximum number of merged findings to AI-triage. Default: 25.",
          default:     25,
        },
      },
      required: ["target_path"],
    },
  },
  {
    name:        "run_recon",
    description: "Crawl a web application and map its attack surface — discovering endpoints, classifying them (API, auth, static, etc.), and producing a surface report with an LLM-written summary.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type:        "string",
          description: "The target URL to crawl (e.g. https://example.com).",
        },
        max_depth: {
          type:        "number",
          description: "Maximum crawl depth from the seed URL. Default: 2.",
          default:     2,
        },
        max_pages: {
          type:        "number",
          description: "Maximum number of pages to visit. Default: 30.",
          default:     30,
        },
      },
      required: ["url"],
    },
  },
  {
    name:        "run_header_audit",
    description: "Crawl a web application and audit its HTTP security headers and cookies against OWASP best practices (CSP, HSTS, X-Frame-Options, SameSite cookies, CORS, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type:        "string",
          description: "The target URL to audit (e.g. https://example.com).",
        },
        max_depth: {
          type:        "number",
          description: "Maximum crawl depth. Default: 2.",
          default:     2,
        },
        max_pages: {
          type:        "number",
          description: "Maximum pages to audit. Default: 30.",
          default:     30,
        },
      },
      required: ["url"],
    },
  },
];

// ── MCP Server setup ─────────────────────────────────────────────────────────

const server = new Server(
  { name: "secura", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "run_static_scan":  return await runStaticScan(args);
      case "run_recon":        return await runRecon(args);
      case "run_header_audit": return await runHeaderAudit(args);
      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error: ${err.message}` }],
      isError: true,
    };
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
// Server runs until the editor closes stdin.
