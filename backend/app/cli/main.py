"""`secura` — command-line entry point for the Static Analysis flow.

    secura scan ./my-repo
    secura scan https://github.com/owner/repo
    secura scan owner/repo

Passes a local repository path — or a public Git repo URL, which the graph
shallow-clones to a temp folder — straight into the Static Analysis LangGraph and
renders the run live in the terminal: the five scanners as they finish, the merge
barrier, the RAG-enriched triage loop, then the generated fixes.

Because the five scanners occupy one LangGraph superstep, the four fast tools
report while CodeQL is still building its database — the tool table updates in
place as each one lands rather than waiting for the slowest.

Commands:
    scan     Run the static analysis flow against a local path.
    tools    Report which scanner binaries are installed and on PATH.
    version  Print the CLI version.

Imports of the graph itself are deferred into the command bodies: pulling in
LangGraph, FastEmbed and the Upstash client costs seconds, and `secura --help`
should not pay for it.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

app = typer.Typer(
    name="secura",
    help="AuthTrack security scanners — static analysis (SAST) from the command line.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

# ── Presentation tables ──────────────────────────────────────────────────────
# Mirrors frontend/src/lib/static-analysis.ts so the CLI and the web UI describe
# the same five engines in the same words.

TOOL_ORDER = ["semgrep", "bearer", "osv-scanner", "gitleaks", "codeql"]

TOOL_KIND = {
    "semgrep": "SAST",
    "bearer": "SAST + privacy",
    "osv-scanner": "SCA",
    "gitleaks": "Secrets",
    "codeql": "Taint analysis",
}

# Backend graph node name → the tool whose row it fills in.
NODE_TO_TOOL = {
    "run_semgrep": "semgrep",
    "run_bearer": "bearer",
    "run_osv_scanner": "osv-scanner",
    "run_gitleaks": "gitleaks",
    "run_codeql": "codeql",
}

SEVERITY_COLOR = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "bright_black",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

STAGE_LABELS = {
    "dispatch": "Resolving target",
    "scan": "Running 5 scanners in parallel",
    "merge": "Merging and deduplicating",
    "rag": "Retrieving similar known-vulnerable patterns",
    "triage": "AI triage",
    "fixes": "Generating fixes",
    "report": "Building report",
    "done": "Complete",
}


def _severity_text(severity: str) -> Text:
    severity = (severity or "info").lower()
    return Text(severity.upper(), style=SEVERITY_COLOR.get(severity, "white"))


def _bar(done: int, total: int, width: int = 24) -> str:
    """A fixed-width progress bar drawn with block characters."""
    if total <= 0:
        return "░" * width
    filled = max(0, min(width, round(width * done / total)))
    return "█" * filled + "░" * (width - filled)


# ── Live run monitor ─────────────────────────────────────────────────────────

class ScanMonitor:
    """Accumulates graph state updates and renders the current run.

    The graph streams one update per completed node, and the triage loop streams
    one per finding, so this holds the running totals the terminal view needs
    rather than re-deriving them from a partial state snapshot.
    """

    def __init__(self, target: str, include_codeql: bool) -> None:
        self.target = target
        self.include_codeql = include_codeql
        self.started = time.time()
        self.stage = "dispatch"
        self.language = "detecting…"

        # tool name → {"state": pending|running|ok|failed, ...}
        self.tools: dict[str, dict] = {
            name: {"state": "pending", "count": 0, "duration": 0.0, "note": "", "sample": False}
            for name in TOOL_ORDER
        }
        if not include_codeql:
            self.tools["codeql"] = {
                "state": "skipped", "count": 0, "duration": 0.0,
                "note": "skipped (--fast)", "sample": False,
            }

        self.merge_stats: dict = {}
        self.safe_patterns = 0
        self.rag_matched: Optional[int] = None
        self.rag_total = 0

        self.triage_done = 0
        self.triage_total = 0
        self.confirmed = 0
        self.discarded = 0

        self.fixes = 0
        self.report: dict = {}
        self.errors: list[str] = []

    # ── state ingestion ──

    def start_scanners(self) -> None:
        for name, row in self.tools.items():
            if row["state"] == "pending":
                row["state"] = "running"

    def ingest(self, node: str, state: dict) -> None:
        """Fold one `node_update` into the monitor's running totals."""
        state = state or {}

        if node == "dispatch":
            self.language = state.get("codeql_language") or "auto"
            self.stage = "scan"
            self.start_scanners()
            return

        if node in NODE_TO_TOOL:
            tool = NODE_TO_TOOL[node]
            status = (state.get("tool_status") or {}).get(tool, {})
            skipped = "skipped" in str(status.get("note", "")).lower()
            self.tools[tool] = {
                "state": "skipped" if skipped else ("ok" if status.get("ok") else "failed"),
                "count": status.get("finding_count", 0),
                "duration": status.get("duration_s", 0.0),
                "note": status.get("note", ""),
                "sample": bool(status.get("used_sample")),
            }
            return

        if node == "merge_findings":
            self.stage = "merge"
            self.merge_stats = state.get("merge_stats") or {}
            self.safe_patterns = len(state.get("safe_patterns") or [])
            return

        if node == "retrieve_context":
            self.stage = "rag"
            findings = state.get("merged_findings") or []
            self.rag_total = len(findings)
            self.rag_matched = sum(1 for f in findings if (f.get("context") or []))
            return

        if node == "triage":
            self.stage = "triage"
            progress = state.get("triage_progress") or {}
            self.triage_done = progress.get("done", self.triage_done)
            self.triage_total = progress.get("total", self.triage_total)
            return

        if node == "confirm_finding":
            self.confirmed += len(state.get("triaged_findings") or []) or 1
            return

        if node == "discard_finding":
            self.discarded += len(state.get("false_positives") or []) or 1
            return

        if node == "fix_generator":
            self.stage = "fixes"
            self.fixes = len(state.get("fixes") or [])
            self.errors.extend(state.get("errors") or [])
            return

        if node == "report_builder":
            self.stage = "report"
            self.report = state.get("static_report") or {}
            return

    # ── rendering ──

    def _tool_table(self) -> Table:
        table = Table(box=box.SIMPLE_HEAD, pad_edge=False, expand=False,
                      header_style="bold bright_black")
        table.add_column("", width=2, no_wrap=True)
        table.add_column("Scanner", style="bold", no_wrap=True)
        table.add_column("Analysis", style="bright_black", no_wrap=True)
        table.add_column("Raw", justify="right", no_wrap=True)
        table.add_column("Time", justify="right", style="bright_black", no_wrap=True)
        table.add_column("Note", style="bright_black", overflow="ellipsis", max_width=48)

        for name in TOOL_ORDER:
            row = self.tools[name]
            state = row["state"]

            if state == "running":
                mark: object = Spinner("dot", style="blue")
            elif state == "ok":
                mark = Text("✔", style="green")
            elif state == "failed":
                mark = Text("!", style="yellow")
            elif state == "skipped":
                mark = Text("–", style="bright_black")
            else:
                mark = Text("·", style="bright_black")

            count = "—" if state in ("pending", "running") else str(row["count"])
            duration = f"{row['duration']:.1f}s" if row["duration"] else ""
            note = row["note"]
            if row["sample"]:
                note = f"sample data — {note}" if note else "using sample data"

            table.add_row(mark, name, TOOL_KIND[name], count, duration, note)
        return table

    def renderable(self) -> Panel:
        parts: list[object] = []

        header = Text()
        header.append("target   ", style="bright_black")
        header.append(f"{self.target}\n", style="cyan")
        header.append("language ", style="bright_black")
        header.append(f"{self.language}\n", style="white")
        header.append("stage    ", style="bright_black")
        header.append(STAGE_LABELS.get(self.stage, self.stage), style="bold blue")
        header.append(f"   ({time.time() - self.started:.0f}s elapsed)", style="bright_black")
        parts.append(header)
        parts.append(Text())
        parts.append(self._tool_table())

        if self.merge_stats:
            stats = self.merge_stats
            line = Text()
            line.append("merge    ", style="bright_black")
            line.append(f"{stats.get('total_raw', 0)} raw", style="white")
            line.append(" → ", style="bright_black")
            line.append(f"{stats.get('total_after_dedup', 0)} unique", style="bold cyan")
            line.append(
                f"  ({stats.get('duplicates_removed', 0)} duplicates removed, "
                f"{stats.get('multi_tool_confirmed', 0)} multi-tool, "
                f"{stats.get('with_taint_path', 0)} with taint path)",
                style="bright_black",
            )
            parts.append(line)

        if self.safe_patterns:
            parts.append(Text(f"controls {self.safe_patterns} existing security control(s) detected",
                              style="green"))

        if self.rag_matched is not None:
            parts.append(Text(
                f"rag      {self.rag_matched}/{self.rag_total} finding(s) matched a known-vulnerable pattern",
                style="magenta",
            ))

        if self.triage_total:
            line = Text()
            line.append("triage   ", style="bright_black")
            line.append(_bar(self.triage_done, self.triage_total), style="blue")
            line.append(f" {self.triage_done}/{self.triage_total}", style="white")
            line.append("   confirmed ", style="bright_black")
            line.append(str(self.confirmed), style="bold red")
            line.append("   ruled out ", style="bright_black")
            line.append(str(self.discarded), style="bold bright_black")
            parts.append(line)

        if self.fixes:
            parts.append(Text(f"fixes    {self.fixes} remediation(s) generated", style="green"))

        return Panel(
            Group(*parts),
            title="[bold]Static Analysis[/bold]",
            subtitle="[bright_black]5 scanners → merge → RAG triage → fixes[/bright_black]",
            border_style="blue" if self.stage != "done" else "green",
            padding=(1, 2),
        )


# ── Final report rendering ───────────────────────────────────────────────────

def _print_report(report: dict, show_fixes: bool, max_findings: int) -> None:
    """Print the finished report: summary, per-tool accounting, then findings."""
    if not report:
        console.print("[yellow]No report was produced.[/yellow]")
        return

    console.print()
    console.print(Panel(
        report.get("summary", "") or "No summary available.",
        title="[bold]Summary[/bold]",
        border_style="bright_black",
        padding=(1, 2),
    ))

    # ── Headline counters ──
    counters = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    counters.add_column(style="bright_black")
    counters.add_column(style="bold")
    counters.add_row("unique findings", str(report.get("total_after_merge", 0)))
    counters.add_row("confirmed", f"[red]{report.get('confirmed_count', 0)}[/red]")
    counters.add_row("ruled out as false positives", str(report.get("ruled_out_count", 0)))
    if report.get("not_triaged_count"):
        counters.add_row("not triaged (cap reached)", str(report["not_triaged_count"]))
    counters.add_row("fixes generated", f"[green]{report.get('fixes_count', 0)}[/green]")
    counters.add_row("with a CodeQL taint path", str(report.get("with_taint_path_count", 0)))
    console.print(counters)

    # ── Severity breakdown of confirmed findings ──
    severities = report.get("severity_breakdown") or {}
    if severities:
        table = Table(title="Confirmed by severity", box=box.SIMPLE_HEAD,
                      title_style="bold", header_style="bold bright_black")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        for name in ("critical", "high", "medium", "low", "info"):
            if severities.get(name):
                table.add_row(_severity_text(name), str(severities[name]))
        console.print(table)

    # ── Per-tool contribution ──
    per_tool = report.get("findings_per_tool") or {}
    if per_tool:
        table = Table(title="Per-tool contribution", box=box.SIMPLE_HEAD,
                      title_style="bold", header_style="bold bright_black")
        table.add_column("Scanner")
        table.add_column("Raw", justify="right")
        table.add_column("After merge", justify="right")
        table.add_column("Time", justify="right", style="bright_black")
        for name in TOOL_ORDER:
            entry = per_tool.get(name)
            if not entry:
                continue
            table.add_row(
                name,
                str(entry.get("raw", 0)),
                str(entry.get("after_merge", 0)),
                f"{entry.get('duration_s', 0):.1f}s",
            )
        console.print(table)

    # ── Confirmed findings ──
    confirmed = report.get("confirmed_findings") or []
    if confirmed:
        console.print()
        console.print("[bold]Confirmed findings[/bold]")
        for finding in confirmed[:max_findings]:
            evidence = (
                "taint path" if finding.get("taint_path")
                else "multi-tool" if finding.get("multi_tool_confirmed")
                else "single tool"
            )
            head = Text("  ")
            head.append(_severity_text(finding.get("final_severity") or finding.get("severity")))
            head.append(f"  {finding.get('category')}", style="bold")
            head.append(f"  {finding.get('file')}:{finding.get('line')}", style="cyan")
            head.append(f"  [{evidence}]", style="bright_black")
            console.print(head)
            console.print(f"      [bright_black]{finding.get('rule_id')}[/bright_black]")
            reason = (finding.get("triage_reason") or "").strip()
            if reason:
                console.print(f"      {reason}")
            if finding.get("taint_path"):
                chain = " → ".join(
                    f"{step.get('file')}:{step.get('line')}" for step in finding["taint_path"]
                )
                console.print(f"      [green]flow:[/green] [bright_black]{chain}[/bright_black]")
            console.print()

        if len(confirmed) > max_findings:
            console.print(f"  [bright_black]…and {len(confirmed) - max_findings} more "
                          f"(raise with --max-findings)[/bright_black]\n")

    # ── Existing security controls ──
    safe = report.get("safe_patterns") or []
    if safe:
        console.print("[bold green]Security controls already in place[/bold green]")
        for pattern in safe:
            console.print(f"  [green]✔[/green] {pattern.get('description')}")
            console.print(f"      [bright_black]{pattern.get('path')}:{pattern.get('line')}[/bright_black]")
        console.print()

    # ── Fixes ──
    fixes = report.get("fixes") or []
    if fixes and show_fixes:
        console.print("[bold]Generated fixes[/bold]")
        for fix in fixes:
            console.print(f"  [cyan]{fix.get('file')}:{fix.get('line')}[/cyan] "
                          f"[bright_black]({fix.get('rule_id')}, grounded in "
                          f"{fix.get('grounded_in')})[/bright_black]")
            console.print(Panel(fix.get("diff_text", ""), border_style="bright_black",
                                padding=(0, 1)))
            if fix.get("explanation"):
                console.print(f"  {fix['explanation']}\n")
    elif fixes:
        console.print(f"[bright_black]{len(fixes)} fix(es) generated — "
                      f"rerun with --show-fixes to print the diffs.[/bright_black]")

    errors = report.get("errors") or []
    if errors:
        console.print()
        console.print("[yellow]Warnings[/yellow]")
        for error in errors:
            console.print(f"  [yellow]•[/yellow] [bright_black]{error}[/bright_black]")


# ── The scan command ─────────────────────────────────────────────────────────

async def _run_scan(
    target: str,
    include_codeql: bool,
    language: str,
    max_triage: int,
    persist: bool,
    quiet: bool,
) -> tuple[dict, list[str]]:
    """Drive the graph, updating the live view, and return (report, errors)."""
    # Deferred so `--help` and `tools` do not pay the import cost.
    from app.agents.static_analysis.graph import (
        static_analysis_graph,
        triage_recursion_limit,
    )

    initial_state = {
        "target_path": target,
        "include_codeql": include_codeql,
        "codeql_language": language,
        "max_triage": max_triage,
        "semgrep_results": [],
        "bearer_results": [],
        "osv_results": [],
        "gitleaks_results": [],
        "codeql_results": [],
        "tool_status": {},
        "merged_findings": [],
        "merge_stats": {},
        "safe_patterns": [],
        "triage_index": 0,
        "triage_cache": {},
        "triaged_findings": [],
        "false_positives": [],
        "fixes": [],
        "static_report": {},
        "errors": [],
    }

    if persist:
        scan_id, flow_run_id = _create_scan_rows(target)
        initial_state["scan_id"] = scan_id
        initial_state["flow_run_id"] = flow_run_id

    monitor = ScanMonitor(target, include_codeql)
    config = {"recursion_limit": triage_recursion_limit(max_triage)}

    if quiet:
        async for chunk in static_analysis_graph.astream(initial_state, config=config):
            for node, state in chunk.items():
                monitor.ingest(node, state)
    else:
        with Live(monitor.renderable(), console=console, refresh_per_second=8,
                  transient=False) as live:
            async for chunk in static_analysis_graph.astream(initial_state, config=config):
                for node, state in chunk.items():
                    monitor.ingest(node, state)
                live.update(monitor.renderable())
            monitor.stage = "done"
            live.update(monitor.renderable())

    return monitor.report, monitor.errors


def _create_scan_rows(target: str) -> tuple[Optional[int], Optional[int]]:
    """Open the NeonDB scan + flow_run rows this run writes its findings under.

    A database that is unreachable must not stop a local scan, so a failure here
    downgrades to an in-memory run instead of aborting.
    """
    try:
        from app.db.models import FlowRun, Scan
        from app.db.session import SessionLocal
    except Exception as exc:
        console.print(f"[yellow]Database unavailable ({exc}) — running without persistence.[/yellow]")
        return None, None

    db = SessionLocal()
    try:
        scan = Scan(target=target, scan_type="static")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        flow = FlowRun(scan_id=scan.id, flow_name="static_analysis")
        db.add(flow)
        db.commit()
        db.refresh(flow)
        return scan.id, flow.id
    except Exception as exc:
        db.rollback()
        console.print(f"[yellow]Could not open a scan record ({exc}) — "
                      f"running without persistence.[/yellow]")
        return None, None
    finally:
        db.close()


@app.command()
def scan(
    target: str = typer.Argument(
        ".",
        metavar="TARGET",
        help="Local repository/folder path, or a public Git repo URL "
             "(https://github.com/owner/repo, git@…, or owner/repo shorthand).",
    ),
    fast: bool = typer.Option(
        False, "--fast", "-f",
        help="Skip CodeQL. Its database-build step dominates the run; the other "
             "four scanners still cover patterns, dependencies and secrets.",
    ),
    language: str = typer.Option(
        "", "--language", "-l",
        help="CodeQL extractor language (javascript, python, java, go, ruby, "
             "csharp, cpp). Auto-detected when omitted.",
    ),
    max_triage: int = typer.Option(
        25, "--max-triage", "-t", min=0,
        help="Cap on how many merged findings get an LLM triage pass. Findings are "
             "ordered strongest-evidence-first, so a cap trims the tail.",
    ),
    fail_on: str = typer.Option(
        "", "--fail-on",
        help="Exit non-zero if any confirmed finding is at or above this severity "
             "(critical, high, medium, low). For use as a CI gate.",
    ),
    json_out: Optional[Path] = typer.Option(
        None, "--json", "-o",
        help="Write the full report as JSON to this path.",
    ),
    no_db: bool = typer.Option(
        False, "--no-db",
        help="Do not write findings to NeonDB — report to the terminal only.",
    ),
    show_fixes: bool = typer.Option(
        False, "--show-fixes",
        help="Print the generated fix diffs in full.",
    ),
    max_findings: int = typer.Option(
        20, "--max-findings", min=1,
        help="How many confirmed findings to print.",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress the live view; print only the final report.",
    ),
) -> None:
    """Run static analysis over a local repository.

    Fans out to Semgrep, Bearer, OSV-Scanner, Gitleaks and CodeQL at once, merges
    their findings into one deduplicated set, retrieves similar known-vulnerable
    patterns from Upstash Vector, then has an LLM confirm or rule out each finding
    and write a patch for the ones it confirms.
    """
    # A target is either a local path or a Git URL. The graph's dispatch node
    # clones a URL to a temp dir transparently, so we only need to reject a
    # string that is neither an existing path nor a recognizable repo URL.
    from app.agents.static_analysis.tools import is_git_url

    target = target.strip()
    is_repo = is_git_url(target)
    if not is_repo:
        resolved = Path(target).expanduser()
        if not resolved.exists():
            console.print(f"[bold red]Not found:[/bold red] '{target}' is neither an "
                          "existing path nor a Git repo URL.")
            raise typer.Exit(code=2)
        if not resolved.is_dir():
            console.print(f"[bold red]Not a directory:[/bold red] {target}")
            raise typer.Exit(code=2)
        target = str(resolved.resolve())

    if not quiet:
        console.print()
        console.print(f"[bold]secura[/bold] scanning [cyan]{target}[/cyan]")
        if is_repo:
            console.print("[bright_black]remote repo — shallow-cloned to a temp folder, "
                          "scanned, then removed[/bright_black]")
        if fast:
            console.print("[bright_black]--fast: CodeQL skipped, "
                          "no taint paths in this run[/bright_black]")
        console.print()

    try:
        report, errors = asyncio.run(_run_scan(
            target=target,
            include_codeql=not fast,
            language=language,
            max_triage=max_triage,
            persist=not no_db,
            quiet=quiet,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(code=130)
    except Exception as exc:
        console.print(f"\n[bold red]Scan failed:[/bold red] {exc}")
        raise typer.Exit(code=2)

    _print_report(report, show_fixes=show_fixes, max_findings=max_findings)

    if json_out:
        try:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            console.print(f"\n[green]Report written to[/green] [cyan]{json_out}[/cyan]")
        except OSError as exc:
            console.print(f"\n[yellow]Could not write {json_out}: {exc}[/yellow]")

    # ── CI gate ──
    if fail_on:
        threshold = SEVERITY_RANK.get(fail_on.lower())
        if threshold is None:
            console.print(f"[yellow]Unknown --fail-on severity '{fail_on}' — ignored.[/yellow]")
        else:
            breaching = [
                finding for finding in (report.get("confirmed_findings") or [])
                if SEVERITY_RANK.get(
                    (finding.get("final_severity") or finding.get("severity") or "info").lower(), 0
                ) >= threshold
            ]
            if breaching:
                console.print(f"\n[bold red]{len(breaching)} confirmed finding(s) at or above "
                              f"{fail_on.upper()}.[/bold red]")
                raise typer.Exit(code=1)
            console.print(f"\n[green]No confirmed findings at or above "
                          f"{fail_on.upper()}.[/green]")


@app.command()
def tools() -> None:
    """Report which scanner binaries are installed and on PATH.

    A missing tool never fails a scan — its runner falls back to representative
    sample findings so the merge, RAG and triage stages still have data — but a
    real scan needs the real binaries.
    """
    from app.agents.static_analysis.tools import _which

    installs = {
        "semgrep": "pip install semgrep    (bundled in this project's dependencies)",
        "bearer": "https://docs.bearer.com/reference/installation/",
        "osv-scanner": "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
        "gitleaks": "https://github.com/gitleaks/gitleaks#installing",
        "codeql": "https://github.com/github/codeql-cli-binaries/releases",
    }

    table = Table(box=box.SIMPLE_HEAD, header_style="bold bright_black")
    table.add_column("Scanner", style="bold")
    table.add_column("Analysis", style="bright_black")
    table.add_column("Status")
    table.add_column("Location / install", style="bright_black", overflow="fold")

    missing = 0
    for name in TOOL_ORDER:
        found = _which(name)
        if found:
            table.add_row(name, TOOL_KIND[name], "[green]installed[/green]", found)
        else:
            missing += 1
            table.add_row(name, TOOL_KIND[name], "[yellow]not found[/yellow]", installs[name])

    console.print()
    console.print(table)
    if missing:
        console.print(f"\n[yellow]{missing} of {len(TOOL_ORDER)} scanners are missing.[/yellow] "
                      "[bright_black]Those runners will emit sample findings instead.[/bright_black]")
    else:
        console.print("\n[green]All five scanners are installed.[/green]")


@app.command()
def version() -> None:
    """Print the CLI version."""
    console.print("secura 0.1.0 — AuthTrack static analysis CLI")


def main() -> None:
    """Console-script entry point."""
    # Running `python app/cli/main.py` directly leaves the backend root off
    # sys.path, so `import app.…` would fail. Add it before Typer dispatches.
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    app()


if __name__ == "__main__":
    main()
