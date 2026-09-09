"use client";

/**
 * One scan flow, end to end: the input form, the live pipeline view, and the
 * post-run actions.
 *
 * Everything that differs between the four flows is data — the metadata in
 * `SCAN_FLOWS`, the stage layout from `stagesForMode`, and whether the input is
 * a URL or a local path. The run itself is entirely in `useScanRun`, so this
 * component is just presentation wired to that hook, and each route page is a
 * one-liner that names its mode.
 */

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity, CheckCircle2, FileText, FolderGit2, Globe, Loader2, XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { ScanPipeline } from "@/components/ui/scan-pipeline";
import { flowByMode, stagesForMode, type ScanMode } from "@/lib/scan-flows";
import { useScanRun } from "@/components/scan/use-scan-run";
import { ScanTabs } from "@/components/scan/scan-tabs";
import { CliHint, isGitUrl } from "@/components/scan/cli-hint";
import { CliInstall } from "@/components/scan/cli-install";

export function ScanRunner({ mode }: { mode: ScanMode }) {
  const router = useRouter();
  const flow = flowByMode(mode);
  const stages = stagesForMode(mode);

  const {
    scanning, scanComplete, error, activity, statuses, results, progressPct, start, reset,
  } = useScanRun(mode);

  const [target, setTarget] = useState("");
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(15);
  const [includeCodeql, setIncludeCodeql] = useState(true);

  const isPath = flow.input === "path";
  const isGitTarget = isPath && isGitUrl(target);
  const canStart = target.trim().length > 0 && !scanning;

  const handleStart = () => {
    if (!canStart) return;
    start({ target: target.trim(), maxDepth, maxPages, includeCodeql });
  };

  const Icon = flow.icon;
  const showPipeline = scanning || scanComplete || Object.keys(results).length > 0;

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6">
      <ScanTabs />

      {/* Flow header */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2.5">
          <Icon className="h-6 w-6" style={{ color: flow.accent }} />
          <h2 className="text-xl font-semibold tracking-tight text-foreground">{flow.label}</h2>
        </div>
        <p className="text-sm leading-6 text-muted-foreground">{flow.description}</p>
      </div>

      {/* SAST leads with the CLI: install + usage up top, the form below as a
          secondary path. Other flows have no CLI, so they skip straight to the form. */}
      {mode === "static" && (
        <>
          <CliInstall />
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-border" />
            <span className="text-xs text-muted-foreground">
              Prefer the browser? Run it in the form below
            </span>
            <div className="h-px flex-1 bg-border" />
          </div>
        </>
      )}

      {/* Input + facts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="flex flex-col gap-5 lg:col-span-7">
          <div>
            <Label htmlFor="scan-target" className="font-medium">
              {isPath ? "GitHub Repo URL or Local Path" : "Target URL"}
            </Label>
            <div className="relative mt-2">
              {isPath ? (
                <FolderGit2 className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
              ) : (
                <Globe className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
              )}
              <Input
                id="scan-target"
                type={isPath ? "text" : "url"}
                className={`h-11 bg-background pl-10 focus-visible:ring-primary ${isPath ? "font-mono" : ""}`}
                placeholder={isPath ? "https://github.com/owner/repo  ·  owner/repo  ·  C:\\path\\to\\repo" : "https://example.com"}
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleStart()}
                disabled={scanning}
              />
            </div>
            {isPath && isGitTarget && (
              <p className="mt-2 flex items-center gap-1.5 text-xs text-muted-foreground">
                <FolderGit2 className="h-3.5 w-3.5 text-primary" />
                Public repo — it&apos;ll be shallow-cloned to a temp folder, scanned, then deleted.
              </p>
            )}
          </div>

          {isPath ? (
            <label className="flex cursor-pointer items-center gap-2.5 text-sm text-muted-foreground">
              <input
                type="checkbox"
                checked={includeCodeql}
                onChange={(e) => setIncludeCodeql(e.target.checked)}
                disabled={scanning}
                className="h-4 w-4 rounded border-border accent-primary"
              />
              Include CodeQL taint analysis (slower, but proves reachability)
            </label>
          ) : (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="max-depth" className="font-medium">Crawl Depth</Label>
                <Select value={String(maxDepth)} onValueChange={(v) => setMaxDepth(Number(v))} disabled={scanning}>
                  <SelectTrigger id="max-depth" className="mt-2 h-11 w-full bg-background focus:ring-primary">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">1 — Surface only</SelectItem>
                    <SelectItem value="2">2 — One level deep</SelectItem>
                    <SelectItem value="3">3 — Deep crawl</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="max-pages" className="font-medium">Max Pages</Label>
                <Select value={String(maxPages)} onValueChange={(v) => setMaxPages(Number(v))} disabled={scanning}>
                  <SelectTrigger id="max-pages" className="mt-2 h-11 w-full bg-background focus:ring-primary">
                    <SelectValue />
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
          )}

          <Button
            onClick={handleStart}
            disabled={!canStart}
            className="w-full bg-white font-medium text-black transition-colors hover:bg-neutral-200"
          >
            {scanning ? (
              <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Scanning…</>
            ) : (
              <><Activity className="mr-2 h-4 w-4" />Start {flow.short}</>
            )}
          </Button>

          {error && (
            <div className="flex items-center gap-3 rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-destructive">
              <XCircle className="h-5 w-5 shrink-0" />
              <span className="text-sm font-medium">{error}</span>
            </div>
          )}
        </div>

        <div className="lg:col-span-5">
          <div className="rounded-xl border border-border/60 bg-card/60 p-5">
            <p className="text-[13px] font-semibold text-foreground">{flow.tagline}</p>
            <ul className="mt-3 flex flex-col gap-2">
              {flow.bullets.map((b) => (
                <li key={b} className="flex items-start gap-2 text-[13px] text-muted-foreground">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" style={{ color: flow.accent }} />
                  {b}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* SAST is CLI-first: offer the equivalent `secura` command for the terminal. */}
      {isPath && <CliHint path={target} includeCodeql={includeCodeql} />}

      {/* Live pipeline */}
      {showPipeline && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-4">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-sm font-semibold">
                {scanComplete ? (
                  <><CheckCircle2 className="h-4 w-4 text-emerald-500" />Scan Complete</>
                ) : (
                  <><Loader2 className="h-4 w-4 animate-spin text-primary" />Running Agents</>
                )}
              </span>
              <span className="text-sm font-bold text-primary tabular-nums">{progressPct}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full transition-all duration-700 ease-out"
                style={{ width: `${progressPct}%`, background: flow.accent }}
              />
            </div>
            {activity && (
              <p className="border-l-2 pl-3 font-mono text-xs text-muted-foreground" style={{ borderColor: flow.accent }}>
                {activity}
              </p>
            )}
          </div>

          <ScanPipeline stages={stages} statuses={statuses} results={results} />

          {scanComplete && (
            <div className="flex gap-4 pt-1">
              <Button className="flex-1 font-semibold" onClick={() => router.push("/reports")}>
                <FileText className="mr-2 h-4 w-4" />View Report
              </Button>
              <Button
                variant="outline"
                className="flex-1 font-semibold"
                onClick={() => { reset(); setTarget(""); }}
              >
                Scan Again
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default ScanRunner;
