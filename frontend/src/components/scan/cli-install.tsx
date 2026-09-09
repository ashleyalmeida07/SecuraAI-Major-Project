"use client";

/**
 * The CLI-first hero for the Static Analysis tab.
 *
 * SAST's canonical entry point is the `secura` npm CLI: it streams a scan from
 * the backend and renders the report in your terminal, with no Python and no
 * scanners installed locally. This panel leads the page with install + usage;
 * the in-browser form below is the secondary path. It is deliberately static
 * (the form-mirroring, per-input command lives in `CliHint`).
 */

import { useState } from "react";
import { Check, Copy, Package, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";

interface Cmd {
  cmd: string;
  note: string;
}

const INSTALL: Cmd = { cmd: "npm i -g @SecuraAI/secura", note: "Install once (Node ≥ 18)" };

const EXAMPLES: Cmd[] = [
  { cmd: "secura scan .", note: "Scan the current directory" },
  { cmd: "secura scan owner/repo", note: "Scan a public GitHub repo (cloned by the backend)" },
  { cmd: "secura scan . --fast", note: "Skip CodeQL for a quicker pass" },
  { cmd: "secura scan . --fail-on high", note: "CI gate — exit non-zero on a confirmed high+ finding" },
];

function CommandRow({ cmd, note }: Cmd) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked (insecure context / denied permission) — no-op */
    }
  };

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-stretch gap-2">
        <code className="flex-1 overflow-x-auto whitespace-nowrap rounded-md border border-border bg-background px-3 py-2 font-mono text-[12px] text-foreground">
          <span className="select-none text-muted-foreground">$ </span>
          {cmd}
        </code>
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy: ${cmd}`}
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
      {note && <p className="pl-1 text-[11px] leading-5 text-muted-foreground">{note}</p>}
    </div>
  );
}

export function CliInstall() {
  return (
    <div className="rounded-xl border border-border/60 bg-card/60 p-5">
      <div className="flex items-center gap-2.5">
        <Terminal className="h-5 w-5 text-primary" />
        <h3 className="text-[15px] font-semibold text-foreground">Run it from your terminal</h3>
      </div>
      <p className="mt-2 text-[13px] leading-6 text-muted-foreground">
        Static analysis ships as the{" "}
        <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[11px]">secura</code>{" "}
        CLI on npm. It streams the scan from the backend and prints the report in your
        terminal — no Python, no scanners installed locally.
      </p>

      <div className="mt-4 flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            <Package className="h-3.5 w-3.5" />Install
          </span>
          <CommandRow {...INSTALL} />
          <p className="pl-1 text-[11px] leading-5 text-muted-foreground">
            No install?{" "}
            <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[10px]">npx @SecuraAI/secura scan .</code>{" "}
            runs it once.
          </p>
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            Usage
          </span>
          {EXAMPLES.map((c) => (
            <CommandRow key={c.cmd} {...c} />
          ))}
        </div>
      </div>

      <p className="mt-4 text-[11px] leading-5 text-muted-foreground">
        Scanning runs on this SecuraAI backend. Point the CLI at a hosted one with{" "}
        <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[10px]">--api</code>{" "}
        or{" "}
        <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[10px]">SECURA_API</code>;{" "}
        <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[10px]">secura scan --help</code>{" "}
        lists every flag.
      </p>
    </div>
  );
}

export default CliInstall;
