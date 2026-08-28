"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { 
  Bug, Brain, Map, Radio, ClipboardCheck, Scale,
  Globe, ShieldCheck, Search, Loader2, CheckCircle2, XCircle,
  Activity, ArrowRight, Link2, Tag, FileText, AlertTriangle,
  Check, CircleCheck, ExternalLink, Zap
} from "lucide-react";
import { scanFullStream, scanReconStream, scanInjectionStream } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { cn } from "@/lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { AgentPlanning, PlanStep } from "@/components/ui/ai-planning";

type ScanMode = "full" | "recon" | "injection";
type NodeStatus = "idle" | "active" | "done" | "error";

interface AgentNode {
  id: string;
  icon: React.ElementType;
  name: string;
  tool: string;
  description: string;
  activeDesc: string;
  flow: 1 | 2;
}

interface NodeEvent {
  node: string;
  timestamp: string;
  summary: string;
  details: React.ReactNode;
  handoff?: string;
}

const ALL_NODES: AgentNode[] = [
  { id: "crawler", icon: Bug, name: "Crawler Node", tool: "httpx + BeautifulSoup",
    description: "Crawls pages, extracts links, forms and API paths",
    activeDesc: "Crawling target URL and following all links...", flow: 1 },
  { id: "classifier", icon: Brain, name: "Classifier Node", tool: "LLM (AI Model)",
    description: "Classifies each endpoint by type using AI",
    activeDesc: "Sending endpoints to AI for classification...", flow: 1 },
  { id: "surface_report", icon: Map, name: "Surface Report Node", tool: "Pure Logic",
    description: "Assembles the structured attack-surface report",
    activeDesc: "Building attack surface map...", flow: 1 },
  { id: "header_fetcher", icon: Radio, name: "Header Fetcher Node", tool: "httpx",
    description: "Fetches HTTP headers and cookies from each endpoint",
    activeDesc: "Fetching response headers and cookies...", flow: 2 },
  { id: "rule_checker", icon: ClipboardCheck, name: "Rule Checker Node", tool: "Security Rules Engine",
    description: "Validates headers against 10 security rules",
    activeDesc: "Running security rules: HSTS, CSP, X-Frame-Options...", flow: 2 },
  { id: "severity_scorer", icon: Scale, name: "Severity Scorer Node", tool: "LLM (AI Model)",
    description: "AI assigns severity ratings and writes executive summary",
    activeDesc: "AI scoring severities and writing summary...", flow: 2 },
];

const INJECTION_NODES: AgentNode[] = [
  { id: "crawler", icon: Bug, name: "Crawler Node", tool: "httpx + BeautifulSoup",
    description: "Crawls pages, extracts links, forms and API paths",
    activeDesc: "Crawling target URL and following all links...", flow: 1 },
  { id: "classifier", icon: Brain, name: "Classifier Node", tool: "LLM (AI Model)",
    description: "Classifies each endpoint by type using AI",
    activeDesc: "Sending endpoints to AI for classification...", flow: 1 },
  { id: "surface_report", icon: Map, name: "Surface Report Node", tool: "Pure Logic",
    description: "Assembles the structured attack-surface report",
    activeDesc: "Building attack surface map...", flow: 1 },
  { id: "payload_generator", icon: Zap, name: "Payload Generator", tool: "Payload Library",
    description: "Generates SQLi, XSS, and injection payloads for each endpoint",
    activeDesc: "Generating attack payloads for discovered endpoints...", flow: 2 },
  { id: "injector", icon: Activity, name: "Injector Node", tool: "httpx",
    description: "Sends baseline + payload requests and records differences",
    activeDesc: "Sending baseline and injected requests...", flow: 2 },
  { id: "response_analyzer", icon: Brain, name: "Response Analyzer", tool: "LLM (AI Model)",
    description: "AI compares responses to confirm or discard injection flaws",
    activeDesc: "LLM analyzing response differences...", flow: 2 },
  { id: "report_builder", icon: FileText, name: "Report Builder", tool: "LLM + Logic",
    description: "Assembles the final injection report with recommendations",
    activeDesc: "Building injection report with executive summary...", flow: 2 },
];

const RECON_NODES = ALL_NODES.filter((n) => n.flow === 1);
const ALL_FLOW_NODES = ALL_NODES;

function parseCrawlerSummary(state: any) {
  const urls = state?.discovered_urls || [];
  const count = urls.length;
  return {
    summary: `Discovered ${count} URL${count !== 1 ? 's' : ''} on the target`,
    details: (
      <div className="flex flex-col gap-2">
        <p className="text-xs text-muted-foreground">Found the following endpoints:</p>
        <div className="flex flex-col gap-1 max-h-32 overflow-y-auto">
          {urls.slice(0, 10).map((u: any, i: number) => (
            <div key={i} className="flex items-center gap-2 text-xs font-mono">
              <Link2 className="h-3 w-3 text-blue-400 shrink-0" />
              <span className="text-blue-300 truncate">{u.url || u}</span>
              {u.method && <span className="text-muted-foreground bg-muted px-1 rounded">{u.method}</span>}
            </div>
          ))}
          {urls.length > 10 && <p className="text-xs text-muted-foreground">...and {urls.length - 10} more</p>}
        </div>
        <div className="mt-1 p-2 bg-primary/5 border border-primary/20 rounded text-xs text-primary">
          Passing {count} discovered URL{count !== 1 ? 's' : ''} to Classifier Node
        </div>
      </div>
    ),
    handoff: `${count} raw URLs → Classifier Node`
  };
}

function parseClassifierSummary(state: any) {
  const endpoints = state?.classified_endpoints || [];
  const types: Record<string, number> = {};
  endpoints.forEach((e: any) => {
    const t = e.endpoint_type || 'unknown';
    types[t] = (types[t] || 0) + 1;
  });
  return {
    summary: `Classified ${endpoints.length} endpoint${endpoints.length !== 1 ? 's' : ''} into ${Object.keys(types).length} type${Object.keys(types).length !== 1 ? 's' : ''}`,
    details: (
      <div className="flex flex-col gap-2">
        <p className="text-xs text-muted-foreground">AI categorized each endpoint by type:</p>
        <div className="flex flex-wrap gap-2">
          {Object.entries(types).map(([type, count]) => (
            <div key={type} className="flex items-center gap-1 text-xs bg-muted rounded px-2 py-1">
              <Tag className="h-3 w-3 text-primary" />
              <span className="font-medium capitalize">{type}</span>
              <span className="text-muted-foreground">×{count}</span>
            </div>
          ))}
        </div>
        <div className="flex flex-col gap-1 max-h-28 overflow-y-auto mt-1">
          {endpoints.slice(0, 6).map((e: any, i: number) => (
            <div key={i} className="flex items-center gap-2 text-xs font-mono">
              <span className="text-muted-foreground truncate">{e.url}</span>
              <span className="text-green-400 shrink-0 font-medium">{e.endpoint_type}</span>
            </div>
          ))}
        </div>
        <div className="mt-1 p-2 bg-primary/5 border border-primary/20 rounded text-xs text-primary">
          Passing classified endpoint list to Surface Report Node
        </div>
      </div>
    ),
    handoff: `${endpoints.length} classified endpoints → Surface Report Node`
  };
}

function parseSurfaceReportSummary(state: any) {
  const report = state?.surface_report || {};
  const total = report.total_endpoints || 0;
  const summary = report.summary || {};
  return {
    summary: `Built attack surface map with ${total} total endpoint${total !== 1 ? 's' : ''}`,
    details: (
      <div className="flex flex-col gap-2">
        <p className="text-xs text-muted-foreground">Attack surface assembled:</p>
        <div className="grid grid-cols-2 gap-2">
          <div className="p-2 bg-muted rounded text-xs">
            <div className="text-lg font-bold text-foreground">{total}</div>
            <div className="text-muted-foreground">Total Endpoints</div>
          </div>
          {Object.entries(summary).map(([k, v]) => (
            <div key={k} className="p-2 bg-muted rounded text-xs">
              <div className="text-lg font-bold text-foreground">{String(v)}</div>
              <div className="text-muted-foreground capitalize">{k}</div>
            </div>
          ))}
        </div>
        {report.scan_timestamp && (
          <p className="text-xs text-muted-foreground">Scan completed at: {report.scan_timestamp}</p>
        )}
      </div>
    ),
    handoff: report.endpoints ? `Full surface report → Flow 2 Header Fetcher` : `Surface report ready`
  };
}

function parseHeaderFetcherSummary(state: any) {
  const results = state?.header_results || [];
  return {
    summary: `Fetched HTTP headers from ${results.length} endpoint${results.length !== 1 ? 's' : ''}`,
    details: (
      <div className="flex flex-col gap-2">
        <p className="text-xs text-muted-foreground">HTTP response headers collected:</p>
        <div className="flex flex-col gap-1 max-h-32 overflow-y-auto">
          {results.slice(0, 6).map((r: any, i: number) => (
            <div key={i} className="text-xs border border-border/50 rounded p-2 bg-muted/50">
              <div className="font-mono text-blue-300 truncate">{r.url}</div>
              <div className="text-muted-foreground mt-1">
                {r.headers && Object.keys(r.headers).slice(0, 3).map((h) => (
                  <span key={h} className="mr-2">{h}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-1 p-2 bg-primary/5 border border-primary/20 rounded text-xs text-primary">
          Passing {results.length} header sets to Rule Checker Node
        </div>
      </div>
    ),
    handoff: `${results.length} header payloads → Rule Checker Node`
  };
}

function parseRuleCheckerSummary(state: any) {
  const findings = state?.findings || [];
  const bySeverity: Record<string, number> = {};
  findings.forEach((f: any) => {
    const s = f.severity || 'unknown';
    bySeverity[s] = (bySeverity[s] || 0) + 1;
  });
  const colors: Record<string, string> = { critical: 'text-red-500', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400' };
  return {
    summary: `Found ${findings.length} security issue${findings.length !== 1 ? 's' : ''} across ${Object.keys(bySeverity).length} severity level${Object.keys(bySeverity).length !== 1 ? 's' : ''}`,
    details: (
      <div className="flex flex-col gap-2">
        <p className="text-xs text-muted-foreground">Security rule violations detected:</p>
        <div className="flex flex-wrap gap-2">
          {Object.entries(bySeverity).map(([sev, count]) => (
            <div key={sev} className={`flex items-center gap-1 text-xs bg-muted rounded px-2 py-1 ${colors[sev] || 'text-foreground'}`}>
              <AlertTriangle className="h-3 w-3" />
              <span className="font-medium capitalize">{sev}</span>
              <span className="text-muted-foreground">×{count}</span>
            </div>
          ))}
        </div>
        {findings.slice(0, 4).map((f: any, i: number) => (
          <div key={i} className="text-xs border border-border/50 rounded p-2">
            <span className={`font-medium ${colors[f.severity] || ''}`}>[{f.severity?.toUpperCase()}]</span>
            <span className="text-muted-foreground ml-1">{f.header_name}</span>
            {f.description && <p className="text-muted-foreground mt-0.5 line-clamp-1">{f.description}</p>}
          </div>
        ))}
        <div className="mt-1 p-2 bg-primary/5 border border-primary/20 rounded text-xs text-primary">
          Passing {findings.length} findings to Severity Scorer (AI)
        </div>
      </div>
    ),
    handoff: `${findings.length} rule violations → Severity Scorer Node`
  };
}

function parseSeverityScorerSummary(state: any) {
  const report = state?.audit_report || {};
  const summary = report.summary || state?.summary || '';
  const scored = state?.scored_findings || [];
  return {
    summary: `AI scored ${scored.length} finding${scored.length !== 1 ? 's' : ''} and wrote executive summary`,
    details: (
      <div className="flex flex-col gap-2">
        <p className="text-xs text-muted-foreground">AI Analysis complete:</p>
        {summary && (
          <div className="p-3 bg-muted/50 border border-border/50 rounded text-xs text-muted-foreground leading-relaxed">
            {summary}
          </div>
        )}
        {report.total_findings !== undefined && (
          <div className="grid grid-cols-2 gap-2 mt-1">
            <div className="p-2 bg-muted rounded text-xs">
              <div className="text-lg font-bold text-foreground">{report.total_findings}</div>
              <div className="text-muted-foreground">Total Findings</div>
            </div>
            <div className="p-2 bg-green-500/10 rounded text-xs">
              <div className="text-lg font-bold text-green-400">{scored.length}</div>
              <div className="text-muted-foreground">AI Scored</div>
            </div>
          </div>
        )}
        <div className="mt-1 p-2 bg-green-500/10 border border-green-500/30 rounded text-xs text-green-400">
          Full audit report ready. View Dashboard for complete results.
        </div>
      </div>
    ),
    handoff: `Final audit report generated`
  };
}

function parseNodeEvent(nodeName: string, state: any) {
  switch(nodeName) {
    case 'crawler': return parseCrawlerSummary(state);
    case 'classifier': return parseClassifierSummary(state);
    case 'surface_report': return parseSurfaceReportSummary(state);
    case 'header_fetcher': return parseHeaderFetcherSummary(state);
    case 'rule_checker': return parseRuleCheckerSummary(state);
    case 'severity_scorer': return parseSeverityScorerSummary(state);
    case 'payload_generator': {
      const cases = state?.test_cases || [];
      return {
        summary: `Generated ${cases.length} test payload${cases.length !== 1 ? 's' : ''}`,
        details: (
          <div className="flex flex-col gap-2">
            <p className="text-xs text-muted-foreground">Attack payloads generated for injection testing:</p>
            <div className="flex flex-wrap gap-2">
              {['sqli', 'xss', 'command_injection', 'path_traversal'].map(t => {
                const c = cases.filter((tc: any) => tc.injection_type === t).length;
                return c > 0 ? (
                  <div key={t} className="flex items-center gap-1 text-xs bg-muted rounded px-2 py-1">
                    <Zap className="h-3 w-3 text-yellow-400" />
                    <span className="font-medium uppercase">{t.replace('_', ' ')}</span>
                    <span className="text-muted-foreground">{c}</span>
                  </div>
                ) : null;
              })}
            </div>
          </div>
        ),
        handoff: `${cases.length} payloads \u2192 Injector Node`
      };
    }
    case 'injector': {
      const results = state?.injection_results || [];
      const anomalies = results.filter((r: any) => r.payload_reflected || r.sql_error_found || r.status_diff).length;
      return {
        summary: `Tested ${results.length} payload${results.length !== 1 ? 's' : ''} — ${anomalies} anomal${anomalies !== 1 ? 'ies' : 'y'} detected`,
        details: (
          <div className="flex flex-col gap-2">
            <p className="text-xs text-muted-foreground">Baseline vs payload response comparison:</p>
            <div className="grid grid-cols-3 gap-2">
              <div className="p-2 bg-muted rounded text-xs text-center">
                <div className="text-lg font-bold">{results.length}</div>
                <div className="text-muted-foreground">Tested</div>
              </div>
              <div className="p-2 bg-yellow-500/10 rounded text-xs text-center">
                <div className="text-lg font-bold text-yellow-400">{anomalies}</div>
                <div className="text-muted-foreground">Anomalies</div>
              </div>
              <div className="p-2 bg-green-500/10 rounded text-xs text-center">
                <div className="text-lg font-bold text-green-400">{results.length - anomalies}</div>
                <div className="text-muted-foreground">Clean</div>
              </div>
            </div>
          </div>
        ),
        handoff: `${anomalies} anomalies \u2192 Response Analyzer (AI)`
      };
    }
    case 'response_analyzer': {
      const confirmed = state?.confirmed_findings || [];
      const discarded = state?.discarded || [];
      return {
        summary: `AI confirmed ${confirmed.length} finding${confirmed.length !== 1 ? 's' : ''}, discarded ${discarded.length}`,
        details: (
          <div className="flex flex-col gap-2">
            <p className="text-xs text-muted-foreground">LLM analysis results:</p>
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2 bg-red-500/10 rounded text-xs text-center">
                <div className="text-lg font-bold text-red-400">{confirmed.length}</div>
                <div className="text-muted-foreground">Confirmed</div>
              </div>
              <div className="p-2 bg-muted rounded text-xs text-center">
                <div className="text-lg font-bold text-muted-foreground">{discarded.length}</div>
                <div className="text-muted-foreground">Discarded</div>
              </div>
            </div>
            {confirmed.slice(0, 3).map((f: any, i: number) => (
              <div key={i} className="text-xs border border-border/50 rounded p-2">
                <span className="font-medium text-red-400">[{f.severity?.toUpperCase()}]</span>
                <span className="text-muted-foreground ml-1">{f.injection_type} on {f.parameter}</span>
              </div>
            ))}
          </div>
        ),
        handoff: `${confirmed.length} confirmed findings \u2192 Report Builder`
      };
    }
    case 'report_builder': {
      const report = state?.injection_report || {};
      return {
        summary: `Built injection report: ${report.total_confirmed || 0} vulnerabilities found`,
        details: (
          <div className="flex flex-col gap-2">
            <p className="text-xs text-muted-foreground">Injection testing complete:</p>
            {report.summary && (
              <div className="p-3 bg-muted/50 border border-border/50 rounded text-xs text-muted-foreground leading-relaxed">
                {report.summary}
              </div>
            )}
            <div className="mt-1 p-2 bg-green-500/10 border border-green-500/30 rounded text-xs text-green-400">
              Injection report ready. View Reports for complete results.
            </div>
          </div>
        ),
        handoff: `Final injection report generated`
      };
    }
    default: return {
      summary: `${nodeName} node completed`,
      details: <p className="text-xs text-muted-foreground">Node processing complete.</p>,
      handoff: undefined
    };
  }
}

function NodeCard({ node, status, event }: { node: AgentNode, status: NodeStatus, event?: NodeEvent }) {
  const Icon = node.icon;
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    if (status === 'done' && event) setExpanded(true);
  }, [status, event]);

  return (
    <div className={`
      rounded-lg border transition-all duration-300
      ${status === 'active' ? 'border-primary/60 bg-primary/5 shadow-md shadow-primary/10' : 
        status === 'done' ? 'border-green-500/30 bg-green-500/5' :
        status === 'error' ? 'border-destructive/40 bg-destructive/5' :
        'border-border/30 bg-background/50'}
    `}>
      {/* Node Header */}
      <button 
        className="w-full p-4 flex items-center gap-3 text-left"
        onClick={() => status === 'done' && event && setExpanded(!expanded)}
      >
        <div className={`
          w-8 h-8 rounded-full flex items-center justify-center shrink-0 border-2
          ${status === 'done' ? 'border-green-500 text-green-500 bg-green-500/10' : 
            status === 'active' ? 'border-primary text-primary bg-primary/10 animate-pulse' :
            status === 'error' ? 'border-destructive text-destructive' :
            'border-muted-foreground/30 text-muted-foreground/50'}
        `}>
          {status === 'done' ? <CheckCircle2 className="h-4 w-4" /> :
           status === 'error' ? <XCircle className="h-4 w-4" /> :
           <Icon className="h-4 w-4" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-bold text-foreground">{node.name}</h4>
            {status === 'active' && <Loader2 className="h-3 w-3 text-primary animate-spin" />}
          </div>
          <p className="text-xs text-muted-foreground">
            {status === 'active' ? node.activeDesc :
             event ? event.summary :
             node.description}
          </p>
        </div>
        {status === 'done' && event && (
          <span className="text-xs text-muted-foreground shrink-0">
            {expanded ? '▲' : '▼'}
          </span>
        )}
      </button>

      {/* Expanded Details */}
      {expanded && event && (
        <div className="px-4 pb-4 border-t border-border/30 pt-3">
          {event.details}
        </div>
      )}

      {/* Handoff Arrow */}
      {status === 'done' && event?.handoff && (
        <div className="px-4 pb-3 flex items-center gap-2 text-xs text-primary/70">
          <ArrowRight className="h-3 w-3" />
          <span className="font-mono">{event.handoff}</span>
        </div>
      )}
    </div>
  );
}

export default function ScanPage() {
  const router = useRouter();

  useEffect(() => {
    if (!isAuthenticated()) router.push("/login");
  }, [router]);

  const [url, setUrl] = useState("");
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(15);
  const [scanMode, setScanMode] = useState<ScanMode>("full");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nodeStatuses, setNodeStatuses] = useState<Record<string, NodeStatus>>({});
  const [nodeEvents, setNodeEvents] = useState<Record<string, NodeEvent>>({});
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);
  const [scanComplete, setScanComplete] = useState(false);
  const [currentActivity, setCurrentActivity] = useState<string>("");

  const activeNodes = scanMode === "recon" ? RECON_NODES : scanMode === "injection" ? INJECTION_NODES : ALL_FLOW_NODES;
  const flow1Nodes = activeNodes.filter((n) => n.flow === 1);
  const flow2Nodes = activeNodes.filter((n) => n.flow === 2);
  const getNodeStatus = (id: string): NodeStatus => nodeStatuses[id] || "idle";

  const completedCount = Object.values(nodeStatuses).filter((s) => s === "done").length;
  const progressPct = scanning || scanComplete
    ? Math.round((completedCount / activeNodes.length) * 100)
    : 0;
    
  const nodeStatesRef = useRef<Record<string, any>>({});

  const handleScan = async () => {
    if (!url.trim()) { setError("Please enter a target URL"); return; }
    setScanning(true);
    setError(null);
    setScanComplete(false);
    setNodeStatuses({});
    setNodeEvents({});
    setActiveNodeId(null);
    setCurrentActivity("");

    try {
      const handleEvent = (data: any) => {
        if (data.event === "start") {
          setCurrentActivity(data.message);
        }
        else if (data.event === "node_update") {
          const nodeName = data.node;
          
          // Mark previous nodes done, this one active first
          setNodeStatuses(prev => {
            const next = { ...prev };
            let passedCurrent = false;
            activeNodes.forEach(n => {
              if (n.id === nodeName) { passedCurrent = true; }
              else if (!passedCurrent) { next[n.id] = "done"; }
            });
            next[nodeName] = "done"; // this node just finished
            return next;
          });
          setActiveNodeId(null);

          // Store raw state for final reconstruction
          nodeStatesRef.current[nodeName] = data.state;

          // Parse the human-readable event
          const parsed = parseNodeEvent(nodeName, data.state);
          const ts = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });
          setNodeEvents(prev => ({
            ...prev,
            [nodeName]: { node: nodeName, timestamp: ts, ...parsed }
          }));
          setCurrentActivity(`${nodeName} node completed — ${parsed.summary}`);
        }
        else if (data.event === "handoff") {
          setCurrentActivity(data.message);
        }
        else if (data.event === "complete") {
          setCurrentActivity(data.message);
        }
        else if (data.event === "error") {
          setError(data.message);
          setCurrentActivity(`Error: ${data.message}`);
        }
      };

      if (scanMode === "recon") {
        await scanReconStream({ url, max_depth: maxDepth, max_pages: maxPages }, handleEvent);
      } else if (scanMode === "injection") {
        await scanInjectionStream({ url, max_depth: maxDepth, max_pages: maxPages }, handleEvent);
      } else {
        await scanFullStream({ url, max_depth: maxDepth, max_pages: maxPages }, handleEvent);
      }

      const allDone: Record<string, NodeStatus> = {};
      activeNodes.forEach((n) => (allDone[n.id] = "done"));
      setNodeStatuses(allDone);
      setActiveNodeId(null);
      setScanComplete(true);
      setCurrentActivity("Scan complete — all nodes finished.");

      // Reconstruct final payload and save to history
      const finalSurface = nodeStatesRef.current["surface_report"]?.surface_report || {};
      const finalAudit = scanMode === "full" ? (nodeStatesRef.current["severity_scorer"]?.audit_report || {}) : null;
      const finalInjection = scanMode === "injection" ? (nodeStatesRef.current["report_builder"]?.injection_report || {}) : null;
      
      let scanData: any;
      if (scanMode === "recon") {
        scanData = { status: "success", surface_report: finalSurface, errors: [] };
      } else if (scanMode === "injection") {
        scanData = { status: "success", surface_report: finalSurface, injection_report: finalInjection, errors: [] };
      } else {
        scanData = { status: "success", surface_report: finalSurface, header_audit_report: finalAudit, errors: [] };
      }
        
      const newScanRecord = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        url,
        mode: scanMode,
        data: scanData
      };

      const historyRaw = localStorage.getItem("authtrack_scan_history");
      const history = historyRaw ? JSON.parse(historyRaw) : [];
      history.unshift(newScanRecord);
      localStorage.setItem("authtrack_scan_history", JSON.stringify(history));
      
      // Keep sessionStorage for immediate fallback
      sessionStorage.setItem("authtrack_scan_result", JSON.stringify(scanData));
      sessionStorage.setItem("authtrack_scan_mode", scanMode);
      sessionStorage.setItem("authtrack_scan_url", url);

    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Scan failed. Is the backend running?";
      setError(errMsg);
    } finally {
      setScanning(false);
    }
  };

  return (
    <DashboardLayout activeId="scan-static">
      <div className="max-w-5xl mx-auto flex flex-col gap-6">

        <div className="grid grid-cols-1 gap-10 lg:grid-cols-12 lg:gap-12">
          <div className="mt-2 lg:col-span-7">
            <h3 className="text-xl font-semibold text-foreground flex items-center gap-2">
              <Search className="h-6 w-6 text-primary" />
              Configure Security Scan
            </h3>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              Enter a URL to execute a multi-agent security crawl and audit. Watch each AI agent work step by step.
            </p>

            <div className="mt-8 space-y-6">
              <div>
                <Label htmlFor="target-url" className="font-medium">
                  Target URL
                </Label>
                <div className="relative mt-2">
                  <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input 
                    id="target-url" 
                    type="url"
                    className="pl-10 h-11 bg-background focus-visible:ring-primary"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && !scanning && handleScan()}
                    disabled={scanning}
                  />
                </div>
                {!url.trim() && (
                  <p className="mt-2 text-xs text-muted-foreground">
                    Enter a valid URL to enable scan.
                  </p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="max-depth" className="font-medium">
                    Crawl Depth
                  </Label>
                  <Select
                    value={String(maxDepth)}
                    onValueChange={(val) => setMaxDepth(Number(val))}
                    disabled={scanning}
                  >
                    <SelectTrigger id="max-depth" className="mt-2 h-11 w-full bg-background focus:ring-primary">
                      <SelectValue placeholder="Select depth" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 — Surface only</SelectItem>
                      <SelectItem value="2">2 — One level deep</SelectItem>
                      <SelectItem value="3">3 — Deep crawl</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="max-pages" className="font-medium">
                    Max Pages Limit
                  </Label>
                  <Select
                    value={String(maxPages)}
                    onValueChange={(val) => setMaxPages(Number(val))}
                    disabled={scanning}
                  >
                    <SelectTrigger id="max-pages" className="mt-2 h-11 w-full bg-background focus:ring-primary">
                      <SelectValue placeholder="Select limit" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="5">5 Pages (~15s)</SelectItem>
                      <SelectItem value="15">15 Pages (~45s)</SelectItem>
                      <SelectItem value="30">30 Pages (~1.5m)</SelectItem>
                      <SelectItem value="50">50 Pages (~2.5m)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <p className="text-sm text-muted-foreground mt-2">
                For faster results, choose a lower crawl depth and page limit.
              </p>
            </div>

            <h4 className="mt-12 font-medium">
              Scan Mode<span className="text-red-500">*</span>
            </h4>
            <RadioGroup
              value={scanMode}
              onValueChange={(value) => setScanMode(value as ScanMode)}
              disabled={scanning}
              className="mt-4 space-y-4"
            >
              <label
                htmlFor="recon"
                className={cn(
                  "relative block cursor-pointer rounded-md border bg-background transition",
                  scanMode === "recon"
                    ? "border-primary/20 ring-2 ring-primary/20"
                    : "border-border"
                )}
              >
                <div className="flex items-start space-x-4 px-6 py-4">
                  <div className="mt-1 flex h-4 w-4 shrink-0 items-center justify-center">
                    <RadioGroupItem value="recon" id="recon" />
                  </div>
                  <div className="w-full">
                    <div className="leading-6 flex items-center">
                      <span className="font-semibold text-foreground">
                        Recon Only
                      </span>
                    </div>
                    <ul className="mt-2 space-y-1">
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        Surface mapping and crawling
                      </li>
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        Identifies open forms and assets
                      </li>
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        Fastest execution time
                      </li>
                    </ul>
                  </div>
                </div>
                <div className="flex items-center justify-between rounded-b-md border-t border-border bg-muted px-6 py-3">
                  <span className="text-sm text-primary">Map attack surface</span>
                </div>
              </label>

              <label
                htmlFor="full"
                className={cn(
                  "relative block cursor-pointer rounded-md border bg-background transition",
                  scanMode === "full"
                    ? "border-primary/20 ring-2 ring-primary/20"
                    : "border-border"
                )}
              >
                <div className="flex items-start space-x-4 px-6 py-4">
                  <div className="mt-1 flex h-4 w-4 shrink-0 items-center justify-center">
                    <RadioGroupItem value="full" id="full" />
                  </div>
                  <div className="w-full">
                    <div className="leading-6 flex items-center">
                      <span className="font-semibold text-foreground">
                        Full Scan
                      </span>
                      <Badge variant="secondary" className="ml-2">
                        recommended
                      </Badge>
                    </div>
                    <ul className="mt-2 space-y-1">
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        Everything in Recon Only
                      </li>
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        Header security misconfiguration audit
                      </li>
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        Detailed vulnerability reporting
                      </li>
                    </ul>
                  </div>
                </div>
                <div className="flex items-center justify-between rounded-b-md border-t border-border bg-muted px-6 py-3">
                  <span className="text-sm text-primary">Comprehensive audit</span>
                </div>
              </label>

              <label
                htmlFor="injection"
                className={cn(
                  "relative block cursor-pointer rounded-md border bg-background transition",
                  scanMode === "injection"
                    ? "border-primary/20 ring-2 ring-primary/20"
                    : "border-border"
                )}
              >
                <div className="flex items-start space-x-4 px-6 py-4">
                  <div className="mt-1 flex h-4 w-4 shrink-0 items-center justify-center">
                    <RadioGroupItem value="injection" id="injection" />
                  </div>
                  <div className="w-full">
                    <div className="leading-6 flex items-center">
                      <span className="font-semibold text-foreground">
                        Injection Test
                      </span>
                      <Badge variant="secondary" className="ml-2 bg-red-500/10 text-red-400 border-red-500/20">
                        active testing
                      </Badge>
                    </div>
                    <ul className="mt-2 space-y-1">
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        Recon + endpoint discovery
                      </li>
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        SQLi, XSS, Command Injection, Path Traversal
                      </li>
                      <li className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-muted-foreground" />
                        AI-confirmed findings with remediation
                      </li>
                    </ul>
                  </div>
                </div>
                <div className="flex items-center justify-between rounded-b-md border-t border-border bg-muted px-6 py-3">
                  <span className="text-sm text-primary">Active vulnerability testing</span>
                </div>
              </label>
            </RadioGroup>

            {error && (
              <div className="mt-6 bg-destructive/10 border border-destructive/50 text-destructive px-4 py-3 rounded-lg flex items-center gap-3">
                <XCircle className="h-5 w-5 shrink-0" />
                <span className="text-sm font-medium">{error}</span>
              </div>
            )}
          </div>

          <div className="lg:col-span-5">
            <Card className="bg-muted">
              <CardContent className="pt-6">
                <h4 className="text-sm font-semibold text-foreground">
                  About the AI Security Engine
                </h4>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">
                  Our flexible scan modes are designed to adapt to your security needs. Watch live as our multi-agent framework dissects your target.
                </p>
                <ul className="mt-4 space-y-3">
                  <li className="flex items-start space-x-2 text-foreground">
                    <CircleCheck className="h-5 w-5 text-primary shrink-0 mt-0.5" />
                    <span className="text-sm">Powered by LangGraph multi-agent orchestration</span>
                  </li>
                  <li className="flex items-start space-x-2 text-foreground">
                    <CircleCheck className="h-5 w-5 text-primary shrink-0 mt-0.5" />
                    <span className="text-sm">Real-time terminal execution logging</span>
                  </li>
                  <li className="flex items-start space-x-2 text-foreground">
                    <CircleCheck className="h-5 w-5 text-primary shrink-0 mt-0.5" />
                    <span className="text-sm">Identifies endpoints, forms, and hidden assets</span>
                  </li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>

        <Separator className="my-6" />

        <div className="flex items-center justify-end space-x-4">
          <Button 
            onClick={handleScan} 
            disabled={scanning || !url.trim()}
            className="whitespace-nowrap px-8 bg-white hover:bg-neutral-200 text-black font-medium transition-colors border-none"
          >
            {scanning ? (
              <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Scanning...</>
            ) : (
              <><Activity className="mr-2 h-4 w-4" />Start Scan</>
            )}
          </Button>
        </div>

        {/* Step-by-step panel — only shown during/after scan */}
        {(scanning || scanComplete || Object.keys(nodeEvents).length > 0) && (
          <div className="flex flex-col gap-4">
            
            {/* Progress Strip */}
            <div className="bg-card border border-border/50 rounded-xl p-4 flex flex-col gap-3">
              <div className="flex justify-between items-center">
                <span className="text-sm font-semibold flex items-center gap-2">
                  {scanComplete ? <><CheckCircle2 className="h-4 w-4 text-green-500" />Scan Complete</> :
                    <><Loader2 className="h-4 w-4 text-primary animate-spin" />Running AI Agents</>}
                </span>
                <span className="text-sm font-bold text-primary">{progressPct}%</span>
              </div>
              <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
                <div className="h-full bg-primary transition-all duration-700 ease-out rounded-full" style={{ width: `${progressPct}%` }} />
              </div>
              {currentActivity && (
                <p className="text-xs text-muted-foreground font-mono border-l-2 border-primary pl-3">{currentActivity}</p>
              )}
            </div>

            {(() => {
              const planSteps: PlanStep[] = activeNodes.map((node, index) => {
                const status = nodeStatuses[node.id] || "idle";
                const event = nodeEvents[node.id];
                
                // Determine step status
                let mappedStatus: "pending" | "active" | "success" | "error" = "pending";
                if (status === "done") mappedStatus = "success";
                else if (status === "error") mappedStatus = "error";
                // If it's idle, check if previous is done, if so it's active. If first node, it's active when scanning.
                else if (scanning) {
                  if (index === 0 && !nodeStatuses[node.id]) mappedStatus = "active";
                  else if (index > 0 && nodeStatuses[activeNodes[index - 1].id] === "done") mappedStatus = "active";
                }

                const Icon = node.icon;
                
                let content = undefined;
                if (mappedStatus === "success" && event) {
                  content = event.details;
                } else if (mappedStatus === "active") {
                  content = (
                    <div className="space-y-3 font-mono text-[11px] mt-2">
                      <div className="flex items-center gap-2 text-blue-600 dark:text-blue-400 font-medium">
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>{node.activeDesc}</span>
                      </div>
                    </div>
                  );
                }

                return {
                  id: node.id,
                  title: node.name,
                  status: mappedStatus,
                  icon: <Icon className="w-3.5 h-3.5" />,
                  content,
                  defaultExpanded: mappedStatus === "active" || mappedStatus === "error" || mappedStatus === "success"
                };
              });
              
              return <AgentPlanning title="Security Scan Execution" steps={planSteps} />;
            })()}

            {/* Done Actions */}
            {scanComplete && (
              <div className="flex gap-4 pt-2">
                <Button className="flex-1 font-semibold" onClick={() => router.push("/dashboard")}>
                  <FileText className="mr-2 h-4 w-4" /> View Full Dashboard
                </Button>
                <Button variant="outline" className="flex-1 font-semibold" onClick={() => {
                  setScanComplete(false); setNodeStatuses({}); setNodeEvents({}); setCurrentActivity("");
                }}>
                  Scan Again
                </Button>
              </div>
            )}

          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
