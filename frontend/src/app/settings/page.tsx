"use client";

export const dynamic = "force-dynamic";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import {
  Settings, Cpu, ChevronDown, ChevronUp, ExternalLink,
  CheckCircle2, Copy, Check, ToggleLeft, ToggleRight,
  Terminal, Download, Play, Server, Zap, AlertTriangle
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

function getAuthHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("token");
  if (!token || token === "null" || token === "undefined") return {};
  return { Authorization: `Bearer ${token}` };
}

/* ─── Setup Steps Data ─── */
const OLLAMA_SETUP_STEPS = [
  {
    id: 1,
    icon: Download,
    title: "Install Ollama",
    description: "Download and install Ollama on your machine.",
    platforms: [
      { name: "macOS / Linux", command: "curl -fsSL https://ollama.com/install.sh | sh" },
      { name: "Windows", command: "Download from https://ollama.com/download/windows" },
    ],
  },
  {
    id: 2,
    icon: Play,
    title: "Start Ollama Server",
    description: "Ollama runs a local API server on port 11434 by default.",
    platforms: [
      { name: "Terminal", command: "ollama serve" },
    ],
    note: "Ollama starts automatically on macOS after installation.",
  },
  {
    id: 3,
    icon: Terminal,
    title: "Pull a Model",
    description: "Download a model that works well for security analysis.",
    platforms: [
      { name: "Recommended (fast)", command: "ollama pull llama3.1:8b" },
      { name: "Best quality (slow)", command: "ollama pull llama3.1:70b" },
      { name: "Lightweight", command: "ollama pull mistral:7b" },
      { name: "Code-focused", command: "ollama pull codellama:13b" },
    ],
  },
  {
    id: 4,
    icon: CheckCircle2,
    title: "Verify It Works",
    description: "Test that Ollama is running and responding.",
    platforms: [
      { name: "Terminal", command: "curl http://localhost:11434/api/tags" },
    ],
    note: "You should see a JSON response listing your downloaded models.",
  },
];

const RECOMMENDED_MODELS = [
  { name: "llama3.1:8b", size: "~4.7 GB", speed: "Fast", quality: "Good", best_for: "Quick scans, general analysis" },
  { name: "llama3.1:70b", size: "~40 GB", speed: "Slow", quality: "Excellent", best_for: "Deep analysis, complex triage" },
  { name: "mistral:7b", size: "~4.1 GB", speed: "Fast", quality: "Good", best_for: "General purpose, header audit" },
  { name: "codellama:13b", size: "~7.4 GB", speed: "Medium", quality: "Great", best_for: "Static code analysis, fix generation" },
  { name: "deepseek-coder-v2:16b", size: "~8.9 GB", speed: "Medium", quality: "Great", best_for: "Code review, vulnerability detection" },
];

/* ─── Copy Button ─── */
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={handleCopy} className="p-1.5 rounded-md transition-all hover:bg-white/10" title="Copy">
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5 text-white/30 hover:text-white/60" />}
    </button>
  );
}

/* ─── Settings Page ─── */
export default function SettingsPage() {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);

  // LLM settings state
  const [useLocalAI, setUseLocalAI] = useState(false);
  const [ollamaUrl, setOllamaUrl] = useState("http://localhost:11434");
  const [ollamaModel, setOllamaModel] = useState("llama3.1:8b");
  const [ollamaStatus, setOllamaStatus] = useState<"idle" | "checking" | "connected" | "error">("idle");
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [setupOpen, setSetupOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    setMounted(true);
    if (!isAuthenticated()) { router.push("/login"); return; }

    // Load saved preferences from localStorage
    const saved = localStorage.getItem("secura_llm_settings");
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setUseLocalAI(parsed.useLocalAI ?? false);
        setOllamaUrl(parsed.ollamaUrl ?? "http://localhost:11434");
        setOllamaModel(parsed.ollamaModel ?? "llama3.1:8b");
      } catch { /* ignore */ }
    }
  }, [router]);

  /* ─── Check Ollama connection ─── */
  const checkOllamaConnection = async () => {
    setOllamaStatus("checking");
    try {
      const res = await fetch(`${ollamaUrl}/api/tags`, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) throw new Error("Not OK");
      const data = await res.json();
      const models = (data.models || []).map((m: any) => m.name || m.model);
      setAvailableModels(models);
      setOllamaStatus("connected");
    } catch {
      setOllamaStatus("error");
      setAvailableModels([]);
    }
  };

  /* ─── Save settings ─── */
  const handleSave = async () => {
    setSaving(true);
    const prefs = { useLocalAI, ollamaUrl, ollamaModel };
    localStorage.setItem("secura_llm_settings", JSON.stringify(prefs));

    // Also update the backend
    try {
      await fetch(`${API_BASE}/settings/llm`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...getAuthHeaders() },
        body: JSON.stringify({
          use_local_ai: useLocalAI,
          ollama_base_url: ollamaUrl,
          ollama_model: ollamaModel,
        }),
      });
    } catch {
      // Backend update is optional — local settings are saved regardless
    }

    setSaving(false);
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 3000);
  };

  if (!mounted) return null;

  return (
    <DashboardLayout activeId="settings">
      <div className="max-w-3xl mx-auto flex flex-col gap-8">

        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold text-foreground tracking-tight flex items-center gap-3">
            <Settings className="h-7 w-7 text-purple-400" />
            Settings
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Configure your AI model preferences. Use your own local AI for complete privacy.
          </p>
        </div>

        {/* ── AI Model Configuration Card ── */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">

          {/* Card Header */}
          <div className="px-6 py-5 border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-purple-500/10 flex items-center justify-center">
                <Cpu className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <h2 className="text-base font-semibold text-foreground">AI Model</h2>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {useLocalAI ? "Using local Ollama model" : "Using cloud AI (OpenRouter / NVIDIA)"}
                </p>
              </div>
            </div>

            {/* Toggle */}
            <button
              onClick={() => setUseLocalAI(!useLocalAI)}
              className="flex items-center gap-2.5 px-4 py-2 rounded-lg transition-all border"
              style={{
                background: useLocalAI ? "rgba(139, 92, 246, 0.15)" : "rgba(255,255,255,0.03)",
                borderColor: useLocalAI ? "rgba(139, 92, 246, 0.4)" : "rgba(255,255,255,0.08)",
              }}
            >
              {useLocalAI
                ? <ToggleRight className="h-5 w-5 text-purple-400" />
                : <ToggleLeft className="h-5 w-5 text-white/30" />
              }
              <span className="text-sm font-medium" style={{ color: useLocalAI ? "#a78bfa" : "rgba(255,255,255,0.5)" }}>
                Local AI {useLocalAI ? "ON" : "OFF"}
              </span>
            </button>
          </div>

          {/* When Local AI is ON — show Ollama config */}
          {useLocalAI && (
            <div className="px-6 py-5 flex flex-col gap-5">

              {/* Ollama URL */}
              <div className="flex flex-col gap-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Ollama API URL
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={ollamaUrl}
                    onChange={e => setOllamaUrl(e.target.value)}
                    placeholder="http://localhost:11434"
                    className="flex-1 px-3 py-2 rounded-lg bg-background border border-border text-sm text-foreground focus:outline-none focus:border-purple-500/50 transition-colors"
                  />
                  <button
                    onClick={checkOllamaConnection}
                    disabled={ollamaStatus === "checking"}
                    className="px-4 py-2 rounded-lg bg-purple-500/15 border border-purple-500/30 text-purple-400 text-sm font-medium hover:bg-purple-500/25 transition-all disabled:opacity-50"
                  >
                    {ollamaStatus === "checking" ? (
                      <span className="flex items-center gap-1.5">
                        <span className="w-3 h-3 border-2 border-purple-400/30 border-t-purple-400 rounded-full animate-spin" />
                        Checking...
                      </span>
                    ) : "Test Connection"}
                  </button>
                </div>

                {/* Connection status */}
                {ollamaStatus === "connected" && (
                  <div className="flex items-center gap-2 text-xs text-green-400">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Connected — {availableModels.length} model{availableModels.length !== 1 ? "s" : ""} available
                  </div>
                )}
                {ollamaStatus === "error" && (
                  <div className="flex items-center gap-2 text-xs text-red-400">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    Cannot connect to Ollama. Make sure it&apos;s running.
                  </div>
                )}
              </div>

              {/* Model selection */}
              <div className="flex flex-col gap-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Model
                </label>
                {availableModels.length > 0 ? (
                  <select
                    value={ollamaModel}
                    onChange={e => setOllamaModel(e.target.value)}
                    className="px-3 py-2 rounded-lg bg-background border border-border text-sm text-foreground focus:outline-none focus:border-purple-500/50 transition-colors appearance-none cursor-pointer"
                  >
                    {availableModels.map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    value={ollamaModel}
                    onChange={e => setOllamaModel(e.target.value)}
                    placeholder="llama3.1:8b"
                    className="px-3 py-2 rounded-lg bg-background border border-border text-sm text-foreground focus:outline-none focus:border-purple-500/50 transition-colors"
                  />
                )}
                <p className="text-[11px] text-muted-foreground">
                  Enter a model name or connect to Ollama to see available models.
                </p>
              </div>

              {/* Recommended models table */}
              <div className="rounded-lg border border-border overflow-hidden">
                <div className="px-4 py-2.5 bg-white/[0.02] border-b border-border">
                  <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Recommended Models for Security Analysis
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left px-4 py-2 text-muted-foreground font-medium">Model</th>
                        <th className="text-left px-4 py-2 text-muted-foreground font-medium">Size</th>
                        <th className="text-left px-4 py-2 text-muted-foreground font-medium">Speed</th>
                        <th className="text-left px-4 py-2 text-muted-foreground font-medium">Best For</th>
                      </tr>
                    </thead>
                    <tbody>
                      {RECOMMENDED_MODELS.map(m => (
                        <tr key={m.name} className="border-b border-border/50 hover:bg-white/[0.02] transition-colors">
                          <td className="px-4 py-2.5">
                            <button
                              onClick={() => setOllamaModel(m.name)}
                              className="font-mono text-purple-400 hover:text-purple-300 transition-colors"
                            >
                              {m.name}
                            </button>
                          </td>
                          <td className="px-4 py-2.5 text-muted-foreground">{m.size}</td>
                          <td className="px-4 py-2.5">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                              m.speed === "Fast" ? "bg-green-500/15 text-green-400" :
                              m.speed === "Medium" ? "bg-yellow-500/15 text-yellow-400" :
                              "bg-red-500/15 text-red-400"
                            }`}>
                              {m.speed}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-muted-foreground">{m.best_for}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* ── How to Setup Ollama (Dropdown) ── */}
              <div className="rounded-xl border border-border overflow-hidden">
                <button
                  onClick={() => setSetupOpen(!setupOpen)}
                  className="w-full px-5 py-4 flex items-center justify-between hover:bg-white/[0.02] transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <Server className="h-4.5 w-4.5 text-purple-400" />
                    <div className="text-left">
                      <div className="text-sm font-medium text-foreground">How to Setup Ollama</div>
                      <div className="text-[11px] text-muted-foreground mt-0.5">Step-by-step guide to run AI models locally</div>
                    </div>
                  </div>
                  {setupOpen ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </button>

                {setupOpen && (
                  <div className="px-5 pb-5 flex flex-col gap-4 border-t border-border pt-4">

                    {/* Link to Ollama */}
                    <a
                      href="https://ollama.com"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-sm text-purple-400 hover:text-purple-300 transition-colors"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      Visit ollama.com for downloads and docs
                    </a>

                    {/* Steps */}
                    {OLLAMA_SETUP_STEPS.map((step, idx) => {
                      const StepIcon = step.icon;
                      return (
                        <div key={step.id} className="flex gap-4">
                          {/* Step number line */}
                          <div className="flex flex-col items-center">
                            <div className="w-8 h-8 rounded-full bg-purple-500/15 border border-purple-500/30 flex items-center justify-center shrink-0">
                              <span className="text-xs font-bold text-purple-400">{step.id}</span>
                            </div>
                            {idx < OLLAMA_SETUP_STEPS.length - 1 && (
                              <div className="w-px flex-1 bg-purple-500/15 mt-1" />
                            )}
                          </div>

                          {/* Step content */}
                          <div className="flex-1 pb-4">
                            <div className="flex items-center gap-2 mb-1">
                              <StepIcon className="h-4 w-4 text-purple-400" />
                              <h4 className="text-sm font-medium text-foreground">{step.title}</h4>
                            </div>
                            <p className="text-xs text-muted-foreground mb-2">{step.description}</p>

                            {step.platforms.map(p => (
                              <div key={p.name} className="mb-1.5">
                                <span className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium">{p.name}</span>
                                <div className="flex items-center gap-1 mt-0.5 bg-black/30 rounded-md px-3 py-2 border border-white/5 font-mono text-xs text-white/80">
                                  <code className="flex-1 overflow-x-auto whitespace-nowrap">{p.command}</code>
                                  <CopyButton text={p.command} />
                                </div>
                              </div>
                            ))}

                            {step.note && (
                              <p className="text-[11px] text-muted-foreground/70 italic mt-1.5">
                                💡 {step.note}
                              </p>
                            )}
                          </div>
                        </div>
                      );
                    })}

                    {/* Hardware requirements */}
                    <div className="rounded-lg bg-yellow-500/5 border border-yellow-500/15 px-4 py-3">
                      <div className="flex items-center gap-2 mb-1.5">
                        <Zap className="h-3.5 w-3.5 text-yellow-400" />
                        <span className="text-xs font-semibold text-yellow-400">Hardware Requirements</span>
                      </div>
                      <ul className="text-[11px] text-muted-foreground space-y-1">
                        <li>• <strong>7B models</strong> (llama3.1:8b, mistral:7b): 8 GB RAM minimum, any modern GPU helps</li>
                        <li>• <strong>13B models</strong> (codellama:13b): 16 GB RAM recommended</li>
                        <li>• <strong>70B models</strong> (llama3.1:70b): 48+ GB RAM, powerful GPU recommended</li>
                        <li>• Works on CPU-only machines, but GPU acceleration (NVIDIA/Apple Silicon) is much faster</li>
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* When Local AI is OFF — show current cloud info */}
          {!useLocalAI && (
            <div className="px-6 py-5">
              <div className="rounded-lg bg-white/[0.02] border border-border px-4 py-3 flex items-start gap-3">
                <Zap className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm text-foreground font-medium">Cloud AI Active</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Scans are processed using cloud-hosted models (OpenRouter / NVIDIA NIM) configured on the server.
                    Toggle &quot;Local AI&quot; to switch to your own Ollama instance for full privacy — no data leaves your machine.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Save button */}
          <div className="px-6 py-4 border-t border-border flex items-center justify-between">
            <p className="text-[11px] text-muted-foreground">
              {useLocalAI
                ? "Scans will use your local Ollama instance. Ensure it's running before scanning."
                : "Scans will use the cloud AI configured on the server."}
            </p>
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-5 py-2 rounded-lg bg-white text-black text-sm font-medium hover:bg-white/90 transition-all disabled:opacity-50 flex items-center gap-2"
            >
              {saving ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-black/20 border-t-black rounded-full animate-spin" />
                  Saving...
                </>
              ) : saveSuccess ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Saved!
                </>
              ) : (
                "Save Settings"
              )}
            </button>
          </div>
        </div>

      </div>
    </DashboardLayout>
  );
}

