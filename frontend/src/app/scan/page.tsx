"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { isAuthenticated } from "@/utils/auth";
import { DashboardLayout } from "@/components/layout/dashboard-layout";
import { 
  Bug, Brain, Map, Radio, ClipboardCheck, Scale,
  Globe, ShieldCheck, Search, Loader2, CheckCircle2, XCircle,
  Activity, ArrowRight, Link2, Tag, FileText, AlertTriangle
} from "lucide-react";
import { scanFullStream, scanReconStream } from "@/lib/api";
import { Button } from "@/components/ui/button";

type ScanMode = "full" | "recon";
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
  const [scanMode, setScanMode] = useState<ScanMode>("full");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nodeStatuses, setNodeStatuses] = useState<Record<string, NodeStatus>>({});
  const [nodeEvents, setNodeEvents] = useState<Record<string, NodeEvent>>({});
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null);
  const [scanComplete, setScanComplete] = useState(false);
  const [currentActivity, setCurrentActivity] = useState<string>("");

  const activeNodes = scanMode === "recon" ? RECON_NODES : ALL_FLOW_NODES;
  const flow1Nodes = activeNodes.filter((n) => n.flow === 1);
  const flow2Nodes = activeNodes.filter((n) => n.flow === 2);
  const getNodeStatus = (id: string): NodeStatus => nodeStatuses[id] || "idle";

  const completedCount = Object.values(nodeStatuses).filter((s) => s === "done").length;
  const progressPct = scanning || scanComplete
    ? Math.round((completedCount / activeNodes.length) * 100)
    : 0;

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
        await scanReconStream({ url, max_depth: maxDepth }, handleEvent);
      } else {
        await scanFullStream({ url, max_depth: maxDepth }, handleEvent);
      }

      const allDone: Record<string, NodeStatus> = {};
      activeNodes.forEach((n) => (allDone[n.id] = "done"));
      setNodeStatuses(allDone);
      setActiveNodeId(null);
      setScanComplete(true);
      setCurrentActivity("Scan complete — all nodes finished.");

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

        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3 text-foreground">
            <Search className="h-8 w-8 text-primary" />
            Security Scanner
          </h1>
          <p className="text-muted-foreground mt-1">Enter a URL. Watch each AI agent work step by step.</p>
        </div>

        {/* Input Panel */}
        <div className="bg-card border border-border/50 rounded-xl p-6 shadow-sm">
          <div className="flex flex-col gap-5">
            <div className="flex flex-col gap-2">
              <label htmlFor="target-url" className="text-sm font-medium text-foreground">Target URL</label>
              <div className="relative">
                <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                <input
                  id="target-url" type="url"
                  className="block w-full pl-10 pr-3 py-2.5 border border-border/50 rounded-lg bg-background text-foreground focus:ring-2 focus:ring-primary focus:border-primary outline-none transition-all"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !scanning && handleScan()}
                  disabled={scanning}
                />
              </div>
              {!url.trim() && <span className="text-xs text-muted-foreground">Enter a valid URL to enable scan.</span>}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-2">
                <label htmlFor="max-depth" className="text-sm font-medium text-foreground">Crawl Depth</label>
                <select id="max-depth"
                  className="w-full px-3 py-2 border border-border/50 rounded-lg bg-background text-foreground focus:ring-2 focus:ring-primary outline-none"
                  value={maxDepth} onChange={(e) => setMaxDepth(Number(e.target.value))} disabled={scanning}>
                  <option value={1}>1 — Surface only</option>
                  <option value={2}>2 — One level deep</option>
                  <option value={3}>3 — Deep crawl</option>
                </select>
              </div>
              <div className="flex flex-col gap-2">
                <label htmlFor="scan-mode" className="text-sm font-medium text-foreground">Scan Mode</label>
                <select id="scan-mode"
                  className="w-full px-3 py-2 border border-border/50 rounded-lg bg-background text-foreground focus:ring-2 focus:ring-primary outline-none"
                  value={scanMode} onChange={(e) => setScanMode(e.target.value as ScanMode)} disabled={scanning}>
                  <option value="full">Full Scan (Recon + Header Audit)</option>
                  <option value="recon">Recon Only (Surface Mapping)</option>
                </select>
              </div>
            </div>

            <Button size="lg" className="w-full font-semibold" onClick={handleScan} disabled={scanning || !url.trim()}>
              {scanning ? <><Loader2 className="mr-2 h-5 w-5 animate-spin" />Scanning...</> :
                          <><Activity className="mr-2 h-5 w-5" />Start Scan</>}
            </Button>

            {error && (
              <div className="bg-destructive/10 border border-destructive/50 text-destructive px-4 py-3 rounded-lg flex items-center gap-3">
                <XCircle className="h-5 w-5 shrink-0" /><span className="text-sm font-medium">{error}</span>
              </div>
            )}
          </div>
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

            {/* Flow 1 Nodes */}
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2 mb-1">
                <span className="bg-primary/10 text-primary text-xs font-bold px-2 py-1 rounded-md uppercase tracking-wider">Flow 1</span>
                <span className="text-sm text-muted-foreground">Recon & Surface Mapping</span>
              </div>
              {flow1Nodes.map((node) => (
                <NodeCard key={node.id} node={node} status={getNodeStatus(node.id)} event={nodeEvents[node.id]} />
              ))}
            </div>

            {/* Handoff Banner */}
            {scanMode === "full" && (
              <div className="flex items-center gap-3 py-1">
                <div className="flex-1 h-px bg-border/50" />
                <div className="flex items-center gap-2 bg-card border border-border/50 px-3 py-1.5 rounded-full text-xs text-muted-foreground">
                  <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                  Endpoints handed off to Flow 2
                  <ArrowRight className="h-3 w-3 text-primary" />
                </div>
                <div className="flex-1 h-px bg-border/50" />
              </div>
            )}

            {/* Flow 2 Nodes */}
            {scanMode === "full" && (
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2 mb-1">
                  <span className="bg-primary/10 text-primary text-xs font-bold px-2 py-1 rounded-md uppercase tracking-wider">Flow 2</span>
                  <span className="text-sm text-muted-foreground">Header & Cookie Audit</span>
                </div>
                {flow2Nodes.map((node) => (
                  <NodeCard key={node.id} node={node} status={getNodeStatus(node.id)} event={nodeEvents[node.id]} />
                ))}
              </div>
            )}

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
