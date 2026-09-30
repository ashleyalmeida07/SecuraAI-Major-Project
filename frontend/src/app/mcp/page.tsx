"use client";

import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { useState } from "react";
import {
  Terminal, Cpu, Code2, Globe, ShieldCheck,
  Copy, Check, ExternalLink, ChevronDown, ChevronUp
} from "lucide-react";

/* ── tiny helpers ──────────────────────────────────────────────────────────── */

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={copy}
      className="p-1.5 rounded-md transition-colors"
      style={{ color: copied ? "#10b981" : "rgba(255,255,255,0.4)" }}
      title="Copy"
    >
      {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
    </button>
  );
}

function CodeBlock({ code, lang = "json" }: { code: string; lang?: string }) {
  return (
    <div className="relative rounded-lg overflow-hidden border border-border" style={{ background: "#0d0d0f" }}>
      <div className="flex items-center justify-between px-4 py-2 border-b border-border">
        <span className="text-[11px] font-mono text-muted-foreground">{lang}</span>
        <CopyButton text={code} />
      </div>
      <pre className="p-4 text-[13px] font-mono overflow-x-auto leading-relaxed whitespace-pre" style={{ color: "#c9d1d9" }}>
        {code}
      </pre>
    </div>
  );
}

function Accordion({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-4 text-sm font-medium text-left transition-colors hover:bg-white/[0.03]"
        style={{ background: "rgba(255,255,255,0.02)" }}
      >
        {title}
        {open ? <ChevronUp className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />}
      </button>
      {open && <div className="px-5 py-4 border-t border-border text-sm text-muted-foreground leading-relaxed">{children}</div>}
    </div>
  );
}

function ToolCard({ icon: Icon, name, description, color, example }: {
  icon: React.ElementType; name: string; description: string; color: string; example: string;
}) {
  return (
    <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0" style={{ background: `${color}20` }}>
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
        <div>
          <div className="font-mono text-sm font-semibold text-foreground">{name}</div>
          <div className="text-[12px] text-muted-foreground">{description}</div>
        </div>
      </div>
      <div className="rounded-md px-3 py-2 text-[12px] font-mono border border-border/60" style={{ background: "#0d0d0f", color: "rgba(255,255,255,0.5)" }}>
        <span style={{ color: "rgba(255,255,255,0.3)" }}>AI prompt → </span>
        <span style={{ color: "#a484d7" }}>{example}</span>
      </div>
    </div>
  );
}

/* ── snippets ────────────────────────────────────────────────────────────────*/

const CLAUDE_CONFIG = `{
  "mcpServers": {
    "secura": {
      "command": "secura-mcp",
      "env": {
        "SECURA_API": "http://localhost:8000/api/v1",
        "SECURA_TOKEN": "<your-jwt-token>"
      }
    }
  }
}`;

const CURSOR_CONFIG = `{
  "secura": {
    "command": "secura-mcp",
    "env": {
      "SECURA_API": "http://localhost:8000/api/v1",
      "SECURA_TOKEN": "<your-jwt-token>"
    }
  }
}`;

const LOCAL_CONFIG = `{
  "mcpServers": {
    "secura": {
      "command": "node",
      "args": ["/path/to/SecuraAI/cli/bin/secura-mcp.mjs"],
      "env": {
        "SECURA_API": "http://localhost:8000/api/v1"
      }
    }
  }
}`;

const VSCODE_CONFIG = `{
  "mcp": {
    "servers": {
      "secura": {
        "type": "stdio",
        "command": "secura-mcp",
        "env": {
          "SECURA_API": "http://localhost:8000/api/v1"
        }
      }
    }
  }
}`;

const AGY_CONFIG = `{
  "mcpServers": {
    "secura": {
      "command": "secura-mcp",
      "env": {
        "SECURA_API": "http://localhost:8000/api/v1"
      }
    }
  }
}`;

const INSTALL_CMD = `npm i @authtrack/secura`;

/* ── Page ────────────────────────────────────────────────────────────────────*/

type Tab = "overview" | "setup" | "tools" | "faq";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "setup",    label: "Setup Guide" },
  { id: "tools",    label: "Available Tools" },
  { id: "faq",      label: "FAQ" },
];

export default function McpPage() {
  const [tab, setTab] = useState<Tab>("overview");

  return (
    <DashboardLayout activeId="mcp">
      <div className="max-w-4xl mx-auto flex flex-col gap-6">

        {/* Header */}
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0" style={{ background: "rgba(164,132,215,0.15)", border: "1px solid rgba(164,132,215,0.25)" }}>
            <Cpu className="w-6 h-6" style={{ color: "#a484d7" }} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground tracking-tight">MCP Integration</h1>
            <p className="mt-1 text-sm text-muted-foreground max-w-xl">
              Use SecuraAI's security scanners directly from your AI editor (Claude Code, Cursor, Continue).
              Your AI assistant calls the tools automatically — no terminal required.
            </p>
          </div>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 border-b border-border pb-0">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className="px-4 py-2.5 text-sm font-medium transition-colors rounded-t-md -mb-px"
              style={{
                color:       tab === t.id ? "#fff"                        : "rgba(255,255,255,0.45)",
                borderBottom: tab === t.id ? "2px solid #a484d7"          : "2px solid transparent",
                background:  "transparent",
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* ── Overview tab ── */}
        {tab === "overview" && (
          <div className="flex flex-col gap-6">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { icon: Terminal,   color: "#00d4ff", title: "Zero setup for the AI",  body: "Once configured, your editor spawns secura-mcp automatically. You just talk to your AI assistant normally." },
                { icon: Cpu,        color: "#a484d7", title: "Ambient security review", body: "Ask your AI to check for vulnerabilities while you code — it invokes the right scanner and shows you the report inline." },
                { icon: ExternalLink, color: "#10b981", title: "Two entry points, one install", body: "secura → your terminal (one-off scans). secura-mcp → your editor config (always-on background process)." },
              ].map(c => (
                <div key={c.title} className="bg-card border border-border rounded-xl p-5 flex flex-col gap-3">
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${c.color}20` }}>
                    <c.icon className="w-4 h-4" style={{ color: c.color }} />
                  </div>
                  <div className="font-semibold text-sm text-foreground">{c.title}</div>
                  <div className="text-[13px] text-muted-foreground leading-relaxed">{c.body}</div>
                </div>
              ))}
            </div>

            <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-4">
              <div className="text-sm font-semibold text-foreground">How it works</div>
              <ol className="flex flex-col gap-3 text-sm text-muted-foreground">
                {[
                  { n: "1", t: "Install the CLI", b: "npm i @authtrack/secura — this registers both secura and secura-mcp on your PATH." },
                  { n: "2", t: "Configure your editor", b: "Add a single JSON block to your editor's MCP settings pointing at secura-mcp." },
                  { n: "3", t: "Editor spawns the server", b: "From then on, the editor automatically starts secura-mcp as a background process on every session start." },
                  { n: "4", t: "AI calls tools on your behalf", b: 'You say "check this repo for vulnerabilities" and the AI calls run_static_scan and shows you the results.' },
                ].map(s => (
                  <li key={s.n} className="flex gap-3">
                    <span className="flex-none w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold mt-0.5" style={{ background: "rgba(164,132,215,0.2)", color: "#a484d7" }}>{s.n}</span>
                    <div><span className="font-medium text-foreground">{s.t}.</span> {s.b}</div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        )}

        {/* ── Setup tab ── */}
        {tab === "setup" && (
          <div className="flex flex-col gap-6">

            <div className="flex flex-col gap-2">
              <h2 className="text-sm font-semibold text-foreground">Step 1 — Install the CLI</h2>
              <p className="text-sm text-muted-foreground">Run this once in any terminal. Both <code className="font-mono text-xs px-1 py-0.5 rounded bg-white/[0.07]">secura</code> and <code className="font-mono text-xs px-1 py-0.5 rounded bg-white/[0.07]">secura-mcp</code> are registered automatically.</p>
              <CodeBlock code={INSTALL_CMD} lang="bash" />
            </div>

            <div className="flex flex-col gap-2">
              <h2 className="text-sm font-semibold text-foreground">Step 2 — Configure your editor</h2>
              <p className="text-sm text-muted-foreground mb-1">Choose your editor below and paste the config into the correct settings file.</p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Claude Code */}
                <div className="flex flex-col gap-2">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#f97316]" /> Claude Code
                  </div>
                  <p className="text-xs text-muted-foreground">Edit <code className="font-mono px-1 py-0.5 rounded bg-white/[0.07]">~/.claude/claude_desktop_config.json</code></p>
                  <CodeBlock code={CLAUDE_CONFIG} lang="json" />
                </div>
                {/* Cursor */}
                <div className="flex flex-col gap-2">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#00d4ff]" /> Cursor
                  </div>
                  <p className="text-xs text-muted-foreground">Settings → Features → MCP → add:</p>
                  <CodeBlock code={CURSOR_CONFIG} lang="json" />
                </div>
                {/* VS Code */}
                <div className="flex flex-col gap-2">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#0078d4]" /> VS Code
                  </div>
                  <p className="text-xs text-muted-foreground">Add to <code className="font-mono px-1 py-0.5 rounded bg-white/[0.07]">.vscode/mcp.json</code> or User Settings:</p>
                  <CodeBlock code={VSCODE_CONFIG} lang="json" />
                </div>
                {/* Antigravity */}
                <div className="flex flex-col gap-2">
                  <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#a484d7]" /> Antigravity (AGY)
                  </div>
                  <p className="text-xs text-muted-foreground">Edit <code className="font-mono px-1 py-0.5 rounded bg-white/[0.07]">~/.gemini/config/mcp_config.json</code>:</p>
                  <CodeBlock code={AGY_CONFIG} lang="json" />
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <h2 className="text-sm font-semibold text-foreground">Alternative — run from source (no global install)</h2>
              <p className="text-sm text-muted-foreground">If you prefer not to install globally, point the config directly at the local file:</p>
              <CodeBlock code={LOCAL_CONFIG} lang="json" />
            </div>

            <div className="bg-amber-500/10 border border-amber-500/25 rounded-xl p-4 text-sm text-amber-300/80 flex gap-3">
              <span className="text-lg leading-none">⚠️</span>
              <div>
                <span className="font-semibold text-amber-200">SECURA_TOKEN</span> is only required if your backend is deployed with authentication enabled. For a local dev backend it can be left empty or omitted entirely.
              </div>
            </div>
          </div>
        )}

        {/* ── Tools tab ── */}
        {tab === "tools" && (
          <div className="flex flex-col gap-4">
            <p className="text-sm text-muted-foreground">
              These are the four tools exposed to your AI assistant. The AI picks the right one automatically based on what you ask.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <ToolCard
                icon={Code2}
                name="run_static_scan"
                description="SAST — Semgrep, Bearer, OSV-Scanner, Gitleaks, CodeQL + AI triage"
                color="#10b981"
                example="Check this repo for vulnerabilities"
              />
              <ToolCard
                icon={Globe}
                name="run_recon"
                description="Crawl & classify all endpoints of a web application"
                color="#00d4ff"
                example="Map the attack surface of example.com"
              />
              <ToolCard
                icon={ShieldCheck}
                name="run_header_audit"
                description="OWASP security-header & cookie audit (CSP, HSTS, CORS…)"
                color="#a484d7"
                example="Audit the security headers on my staging site"
              />
            </div>

            <div className="bg-card border border-border rounded-xl p-5 flex flex-col gap-3 mt-2">
              <div className="text-sm font-semibold text-foreground">Example prompts you can use</div>
              <div className="flex flex-col gap-2">
                {[
                  { prompt: "\"Check this repo for vulnerabilities\"",           tool: "run_static_scan" },
                  { prompt: "\"Are there any secrets leaked in this codebase?\"", tool: "run_static_scan (Gitleaks)" },
                  { prompt: "\"Map the attack surface of https://example.com\"",  tool: "run_recon" },
                  { prompt: "\"Audit my site's security headers\"",               tool: "run_header_audit" },
                ].map(ex => (
                  <div key={ex.prompt} className="flex items-start gap-3 text-sm">
                    <span className="text-muted-foreground font-mono text-[12px] shrink-0 mt-0.5">{ex.prompt}</span>
                    <span className="text-muted-foreground/50">→</span>
                    <code className="text-[12px] font-mono px-1.5 py-0.5 rounded" style={{ background: "rgba(164,132,215,0.15)", color: "#a484d7" }}>{ex.tool}</code>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── FAQ tab ── */}
        {tab === "faq" && (
          <div className="flex flex-col gap-3">
            {[
              {
                q: "Do I need to keep a terminal open with secura-mcp running?",
                a: "No. Your editor manages the process lifecycle entirely. It starts secura-mcp when you open a session and kills it when you close. You don't interact with it at all."
              },
              {
                q: "Can I use both secura (CLI) and secura-mcp at the same time?",
                a: "Yes. They are completely independent entry points. secura is for when you want to run an on-demand scan in your terminal. secura-mcp is always available in your editor via your AI assistant."
              },
              {
                q: "Does the MCP server need the SecuraAI backend to be running?",
                a: "Yes — it forwards requests to the FastAPI backend. Set SECURA_API to your local backend (http://localhost:8000/api/v1) for development, or to the deployed Render URL for production."
              },
              {
                q: "How do I pass my auth token?",
                a: "Set SECURA_TOKEN in the env block of your MCP config. The server sends it as an Authorization: Bearer <token> header on every request. For a local dev backend without auth, you can omit it."
              },
              {
                q: "What Node version is required?",
                a: "Node ≥ 18. No build step, no native modules — pure ESM."
              },
              {
                q: "Can I add more tools without reinstalling?",
                a: "Yes — edit cli/bin/secura-mcp.mjs directly and restart your editor. You can also send a PR to add new tools (e.g. CORS misconfiguration checker) to the official package."
              },
            ].map(({ q, a }) => (
              <Accordion key={q} title={q}>
                {a}
              </Accordion>
            ))}
          </div>
        )}

      </div>
    </DashboardLayout>
  );
}
