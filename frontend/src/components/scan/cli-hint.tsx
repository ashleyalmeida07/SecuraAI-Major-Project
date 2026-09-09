"use client";

/**
 * A collapsible "run this in your terminal instead" panel for the Static
 * Analysis tab.
 *
 * SAST reads your actual source tree, so its canonical entry point is the
 * `secura` CLI, run right where the code lives. This mirrors the current form
 * state into the equivalent command so the two entry points never drift:
 * turning CodeQL off in the form shows the `--fast` flag in the command.
 */

import { useMemo, useState } from "react";
import { Check, ChevronRight, Copy, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";

/** Quote a target for the shell only when it contains whitespace. */
function quotePath(path: string): string {
  return /\s/.test(path) ? `"${path}"` : path;
}

/**
 * True when the target looks like a Git repository the backend should clone
 * rather than a local path — a full clone URL or GitHub "owner/repo" shorthand.
 * Mirrors `tools.is_git_url` on the backend.
 */
export function isGitUrl(target: string): boolean {
  const t = target.trim();
  if (!t) return false;
  if (/^(https?:\/\/|git@|ssh:\/\/|git:\/\/)/i.test(t)) return true;
  // owner/repo shorthand: exactly one slash, no leading path markers, no spaces.
  return /^[\w.-]+\/[\w.-]+$/.test(t) && !/^[./~]/.test(t);
}

/**
 * The `secura scan` invocation equivalent to the current form. Language and the
 * triage cap are left at their defaults (auto-detect, 25) — the same defaults
 * the web run uses — so the only flag the form can add is `--fast`.
 */
export function buildScanCommand(path: string, includeCodeql: boolean): string {
  const target = path.trim() || ".";
  const parts = ["secura", "scan", quotePath(target)];
  if (!includeCodeql) parts.push("--fast");
  return parts.join(" ");
}

export function CliHint({ path, includeCodeql }: { path: string; includeCodeql: boolean }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const command = useMemo(() => buildScanCommand(path, includeCodeql), [path, includeCodeql]);
  const gitTarget = isGitUrl(path);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked (insecure context / denied permission) — no-op */
    }
  };

  return (
    <div className="rounded-lg border border-border/60 bg-card/40">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-4 py-2.5 text-left text-[13px] font-medium text-muted-foreground transition-colors hover:text-foreground"
        aria-expanded={open}
      >
        <ChevronRight className={cn("h-4 w-4 transition-transform", open && "rotate-90")} />
        <Terminal className="h-4 w-4" />
        Prefer the terminal? Run this scan via the CLI
      </button>

      {open && (
        <div className="flex flex-col gap-2 px-4 pb-4">
          <p className="text-xs leading-5 text-muted-foreground">
            {gitTarget ? (
              <>
                The{" "}
                <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[11px]">secura</code>{" "}
                CLI has the backend clone and scan the repo. This command matches the options above.
              </>
            ) : (
              <>
                The{" "}
                <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[11px]">secura</code>{" "}
                CLI sends this folder to the backend to scan — in place for a local backend, or
                packaged and uploaded for a remote one. This command matches the options above.
              </>
            )}
          </p>
          <div className="flex items-stretch gap-2">
            <code className="flex-1 overflow-x-auto whitespace-nowrap rounded-md border border-border bg-background px-3 py-2.5 font-mono text-[12px] text-foreground">
              <span className="select-none text-muted-foreground">$ </span>
              {command}
            </code>
            <button
              type="button"
              onClick={copy}
              aria-label="Copy command"
              className={cn(
                "flex shrink-0 items-center gap-1.5 rounded-md border px-3 text-[12px] font-medium transition-colors",
                copied
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-500"
                  : "border-border bg-secondary text-muted-foreground hover:text-foreground",
              )}
            >
              {copied ? (
                <><Check className="h-3.5 w-3.5" />Copied</>
              ) : (
                <><Copy className="h-3.5 w-3.5" />Copy</>
              )}
            </button>
          </div>
          <p className="text-[11px] leading-5 text-muted-foreground">
            First time? Install with{" "}
            <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[10px]">npm i -g @SecuraAI/secura</code>{" "}
            (or run it once with{" "}
            <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[10px]">npx @SecuraAI/secura</code>).{" "}
            <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[10px]">secura scan --help</code>{" "}
            lists every flag (<span className="font-mono">--max-triage</span>,{" "}
            <span className="font-mono">--fail-on</span>, <span className="font-mono">--json</span> …).
          </p>
        </div>
      )}
    </div>
  );
}

export default CliHint;
