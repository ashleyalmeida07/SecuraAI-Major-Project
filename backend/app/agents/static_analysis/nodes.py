"""Node functions for the Static Analysis LangGraph flow.

Graph shape:

    dispatch ──┬─► run_semgrep      ─┐
               ├─► run_bearer       ─┤
               ├─► run_osv_scanner  ─┼─► merge_findings ─► retrieve_context
               ├─► run_gitleaks     ─┤
               └─► run_codeql       ─┘
                                                                │
        ┌───────────────────────────────────────────────────────┘
        ▼
    triage ─► (verdict) ─► confirm_finding ─┬─► triage   (more findings)
                        └─► discard_finding ─┴─► fix_generator ─► report_builder

The five scanner nodes have no dependency on one another and are declared as
parallel edges out of `dispatch`, so LangGraph schedules them in a single
superstep. Each one emits its own state update the moment it finishes, which is
what lets the SSE stream show the four fast tools' results while CodeQL — whose
database-build step dominates its runtime — is still working.

Everything after the fan-in is I/O-bound (embeddings, vector queries, LLM
round-trips), so each stage batches or parallelizes its calls rather than issuing
them one at a time:

  · `retrieve_context` embeds every snippet in one FastEmbed pass and runs the
    Upstash queries concurrently.
  · `triage` still visits one finding per superstep so the UI can render
    progress, but a cache miss prefetches a window of verdicts concurrently, so
    the stage costs ceil(n / TRIAGE_PREFETCH) round-trips instead of n.
  · `fix_generator` generates all patches concurrently and commits them in one
    transaction.

Persistence: confirmed and ruled-out findings are written to NeonDB as they are
decided (that is where the verdict exists), fixes are written as they are
generated, and `report_builder` finalizes the scan/flow rows and assembles the
summary object returned to the API.
"""

import asyncio
from datetime import datetime

from pydantic import BaseModel, Field

from app.agents.static_analysis import tools
from app.agents.static_analysis.state import StaticAnalysisState
from app.core.config import settings
from app.core.llm import get_llm
from app.db.models import Finding, Fix, FlowRun, Scan
from app.db.session import SessionLocal
from upstash_vector import Index

# ── Concurrency budgets ──────────────────────────────────────────────────────
# How many triage verdicts to fetch in one concurrent burst on a cache miss.
# The triage loop still yields one finding per superstep for the UI; this only
# controls how many LLM calls are in flight while it does so.
TRIAGE_PREFETCH = 6
# Simultaneous fix-generation LLM calls.
FIX_CONCURRENCY = 5
# Simultaneous Upstash Vector queries.
RAG_CONCURRENCY = 8

# ── Shared clients (lazily initialized, reused across nodes) ─────────────────

try:
    upstash_index = Index(
        url=settings.UPSTASH_SEARCH_REST_URL,
        token=settings.UPSTASH_SEARCH_REST_TOKEN,
    )
except Exception:
    upstash_index = None

_embedder = None


def _get_embedder():
    """Load the FastEmbed model once per process — it is expensive to construct."""
    global _embedder
    if _embedder is None:
        from fastembed import TextEmbedding
        _embedder = TextEmbedding()
    return _embedder


def _embed(text: str) -> list[float]:
    """Embed one string into a query vector."""
    return list(_get_embedder().embed([text]))[0].tolist()


def _embed_many(texts: list[str]) -> list[list[float]]:
    """Embed a batch of strings in a single FastEmbed pass.

    FastEmbed batches internally, so one call over n snippets is dramatically
    cheaper than n calls — the per-call model dispatch overhead dominates at the
    snippet sizes this flow deals with.
    """
    if not texts:
        return []
    return [vector.tolist() for vector in _get_embedder().embed(texts)]


# Structured-output wrappers are rebuilt on every `.with_structured_output()`
# call, so cache them per process rather than per finding.
_triage_llm = None
_fix_llm = None


def _get_triage_llm():
    global _triage_llm
    if _triage_llm is None:
        _triage_llm = get_llm(structured_output=TriageResult)
    return _triage_llm


def _get_fix_llm():
    global _fix_llm
    if _fix_llm is None:
        _fix_llm = get_llm(structured_output=FixResult)
    return _fix_llm


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ── LLM output schemas ───────────────────────────────────────────────────────

class TriageResult(BaseModel):
    verdict: str = Field(description="Either 'confirmed' for a genuine, exploitable vulnerability "
                                     "or 'false_positive' for a non-issue or acceptable risk.")
    reason: str = Field(description="2-4 sentences justifying the verdict. If a CodeQL taint path "
                                    "was supplied, explicitly reference its source and sink.")
    severity: str = Field(description="Final severity for a confirmed finding: "
                                      "critical, high, medium, or low. Use 'info' for a false positive.")
    confidence: str = Field(default="medium", description="Confidence in this verdict: high, medium, or low.")


class FixResult(BaseModel):
    diff_text: str = Field(description="The corrected code, as a unified diff or a replacement snippet.")
    explanation: str = Field(description="Why this change removes the vulnerability.")


# ── Node 0: dispatch (graph entry / fan-out origin) ──────────────────────────

async def dispatch_scan(state: StaticAnalysisState) -> dict:
    """Resolve scan parameters, then fan out to all five scanners.

    Auto-detects the CodeQL extractor language when the caller did not pin one,
    since `codeql database create` requires it up front.
    """
    target = state.get("target_path") or "."

    # If the target is a Git URL (or "owner/repo" shorthand), shallow-clone it to
    # a temp dir and scan the clone. report_builder deletes it when the run ends.
    source_repo = ""
    cloned_repo_dir = ""
    clone_errors: list[str] = []
    if tools.is_git_url(target):
        source_repo = tools.normalize_git_url(target)
        print(f"--- [dispatch] Cloning remote repo {source_repo} ---")
        clone_dir, note = await asyncio.to_thread(tools.clone_repo, target)
        if clone_dir:
            cloned_repo_dir = clone_dir
            target = clone_dir
            print(f"--- [dispatch] {note} → {clone_dir} ---")
        else:
            # Clone failed — surface it and fall back to scanning the CWD so the
            # graph still completes with a clear error rather than crashing.
            clone_errors.append(f"clone: {note}")
            target = "."
            print(f"--- [dispatch] clone failed ({note}); scanning '.' instead ---")

    language = state.get("codeql_language") or ""
    if not language:
        try:
            language = await asyncio.to_thread(tools.detect_language, target)
        except Exception:
            language = "javascript"

    print(f"--- [dispatch] Static analysis on {target} (codeql language: {language}) ---")
    return {
        "target_path": target,
        "source_repo": source_repo,
        "cloned_repo_dir": cloned_repo_dir,
        "codeql_language": language,
        "triage_index": 0,
        "triage_cache": {},
        "tool_status": {},
        "errors": clone_errors,
    }


# ── Fan-out stage: five independent scanners ─────────────────────────────────

async def run_semgrep(state: StaticAnalysisState) -> dict:
    """Semgrep SAST pass over the repository."""
    target = state.get("target_path", ".")
    print("--- [run_semgrep] starting ---")
    findings, status = await asyncio.to_thread(tools.run_semgrep_tool, target)
    print(f"--- [run_semgrep] {len(findings)} finding(s) in {status['duration_s']}s ---")
    return {
        "semgrep_results": findings,
        "tool_status": {"semgrep": status},
        "errors": [] if status["ok"] else [f"semgrep: {status['note']}"],
    }


async def run_bearer(state: StaticAnalysisState) -> dict:
    """Bearer SAST pass (dataflow-aware rules with strong CWE tagging)."""
    target = state.get("target_path", ".")
    print("--- [run_bearer] starting ---")
    findings, status = await asyncio.to_thread(tools.run_bearer_tool, target)
    print(f"--- [run_bearer] {len(findings)} finding(s) in {status['duration_s']}s ---")
    return {
        "bearer_results": findings,
        "tool_status": {"bearer": status},
        "errors": [] if status["ok"] else [f"bearer: {status['note']}"],
    }


async def run_osv_scanner(state: StaticAnalysisState) -> dict:
    """OSV-Scanner pass over lockfiles for known-vulnerable dependencies."""
    target = state.get("target_path", ".")
    print("--- [run_osv_scanner] starting ---")
    findings, status = await asyncio.to_thread(tools.run_osv_tool, target)
    print(f"--- [run_osv_scanner] {len(findings)} finding(s) in {status['duration_s']}s ---")
    return {
        "osv_results": findings,
        "tool_status": {"osv-scanner": status},
        "errors": [] if status["ok"] else [f"osv-scanner: {status['note']}"],
    }


async def run_gitleaks(state: StaticAnalysisState) -> dict:
    """Gitleaks pass for hardcoded secrets (values redacted on the way out)."""
    target = state.get("target_path", ".")
    print("--- [run_gitleaks] starting ---")
    findings, status = await asyncio.to_thread(tools.run_gitleaks_tool, target)
    print(f"--- [run_gitleaks] {len(findings)} finding(s) in {status['duration_s']}s ---")
    return {
        "gitleaks_results": findings,
        "tool_status": {"gitleaks": status},
        "errors": [] if status["ok"] else [f"gitleaks: {status['note']}"],
    }


async def run_codeql(state: StaticAnalysisState) -> dict:
    """CodeQL pass — builds a database, then runs the security query suite.

    Substantially slower than the other four (the database build alone can take
    minutes), and the only tool here that yields full source → sink taint paths.
    """
    if not state.get("include_codeql", True):
        return {
            "codeql_results": [],
            "tool_status": {"codeql": tools.make_status("codeql", True, 0, "skipped by request")},
        }

    target = state.get("target_path", ".")
    language = state.get("codeql_language") or "javascript"
    print(f"--- [run_codeql] starting two-step run (language: {language}) ---")
    findings, status = await asyncio.to_thread(tools.run_codeql_tool, target, language)
    with_paths = sum(1 for f in findings if f.get("taint_path"))
    print(f"--- [run_codeql] {len(findings)} finding(s), {with_paths} with taint paths, "
          f"in {status['duration_s']}s ---")
    return {
        "codeql_results": findings,
        "tool_status": {"codeql": status},
        "errors": [] if status["ok"] else [f"codeql: {status['note']}"],
    }


# ── Fan-in stage: merge & dedupe ─────────────────────────────────────────────

def _dedup_key(finding: dict) -> tuple:
    """Identity used to recognize the same defect reported by different tools.

    Dependency findings are keyed by advisory + package (line numbers are
    meaningless in a lockfile); code findings are keyed by file, category, and a
    small line bucket, because tools disagree by a line or two on where a
    dataflow issue "is".
    """
    if finding.get("tool_source") == "osv-scanner" or finding.get("package"):
        return ("dep", finding.get("rule_id", ""), finding.get("package", ""))
    line = finding.get("line") or 0
    return ("code", finding.get("file", ""), finding.get("category", ""), line // 3)


async def merge_findings(state: StaticAnalysisState) -> dict:
    """Normalize all five tools' output into one deduplicated finding list.

    Runs once every incoming scanner edge has produced a value, so it is the
    graph's synchronization barrier. Findings reported by more than one tool are
    flagged `multi_tool_confirmed`, and a CodeQL taint path is always carried
    onto the merged record — it is the strongest evidence available and must not
    be flattened away by the merge.
    """
    print("--- [merge_findings] Normalizing and deduplicating tool output ---")

    per_tool = {
        "semgrep": state.get("semgrep_results") or [],
        "bearer": state.get("bearer_results") or [],
        "osv-scanner": state.get("osv_results") or [],
        "gitleaks": state.get("gitleaks_results") or [],
        "codeql": state.get("codeql_results") or [],
    }
    raw_counts = {tool: len(items) for tool, items in per_tool.items()}
    total_raw = sum(raw_counts.values())

    merged: dict[tuple, dict] = {}
    for tool, findings in per_tool.items():
        for finding in findings:
            key = _dedup_key(finding)
            existing = merged.get(key)

            if existing is None:
                merged[key] = {
                    "tool_source": tool,
                    "file": finding.get("file", "unknown"),
                    "line": finding.get("line") or 0,
                    "severity": finding.get("severity", "medium"),
                    "rule_id": finding.get("rule_id", ""),
                    "category": finding.get("category", "Other"),
                    "description": finding.get("description", ""),
                    "raw_snippet": finding.get("raw_snippet", ""),
                    "taint_path": finding.get("taint_path"),
                    "multi_tool_confirmed": False,
                    "confirmed_by": [tool],
                    "cwe": finding.get("cwe", []),
                    "owasp": finding.get("owasp", []),
                    "package": finding.get("package"),
                    "package_version": finding.get("package_version"),
                    "fixed_versions": finding.get("fixed_versions", []),
                    "context": [],
                }
                continue

            # ── Same defect, second reporter: merge rather than duplicate ──
            if tool not in existing["confirmed_by"]:
                existing["confirmed_by"].append(tool)
                existing["multi_tool_confirmed"] = len(existing["confirmed_by"]) > 1

            # Keep the highest severity any tool assigned.
            if SEVERITY_RANK.get(finding.get("severity", "low"), 1) > \
               SEVERITY_RANK.get(existing["severity"], 1):
                existing["severity"] = finding.get("severity", existing["severity"])

            # A taint path is the strongest evidence type — always preserve it,
            # and let CodeQL's richer record win the descriptive fields.
            if finding.get("taint_path") and not existing.get("taint_path"):
                existing["taint_path"] = finding["taint_path"]
                existing["tool_source"] = tool
                existing["rule_id"] = finding.get("rule_id") or existing["rule_id"]
                existing["description"] = finding.get("description") or existing["description"]

            if not existing.get("raw_snippet") and finding.get("raw_snippet"):
                existing["raw_snippet"] = finding["raw_snippet"]
            if not existing.get("cwe") and finding.get("cwe"):
                existing["cwe"] = finding["cwe"]

    findings = list(merged.values())

    # Highest severity first, taint-path and multi-tool evidence promoted — this
    # is also the order the triage loop consumes, so the best evidence is
    # processed first when a max_triage cap applies.
    findings.sort(key=lambda f: (
        SEVERITY_RANK.get(f["severity"], 0),
        1 if f.get("taint_path") else 0,
        1 if f["multi_tool_confirmed"] else 0,
    ), reverse=True)

    multi_tool = sum(1 for f in findings if f["multi_tool_confirmed"])
    with_paths = sum(1 for f in findings if f.get("taint_path"))
    tools_reporting = sum(1 for count in raw_counts.values() if count > 0)

    print(f"--- [merge_findings] {total_raw} raw → {len(findings)} unique "
          f"({multi_tool} multi-tool confirmed, {with_paths} with taint paths) ---")

    # Positive evidence: security controls already present in the codebase.
    # Off the event loop — it walks the tree and runs a regex pass per line.
    try:
        safe_patterns = await asyncio.to_thread(
            tools.detect_safe_patterns, state.get("target_path", ".")
        )
    except Exception as exc:
        print(f"--- [merge_findings] safe-pattern scan failed: {exc} ---")
        safe_patterns = []

    return {
        "merged_findings": findings,
        "safe_patterns": safe_patterns,
        "merge_stats": {
            "raw_per_tool": raw_counts,
            "total_raw": total_raw,
            "total_after_dedup": len(findings),
            "duplicates_removed": total_raw - len(findings),
            "multi_tool_confirmed": multi_tool,
            "with_taint_path": with_paths,
            "tools_reporting": tools_reporting,
            "category_breakdown": _count_by(findings, "category"),
            "severity_breakdown": _count_by(findings, "severity"),
        },
    }


def _count_by(items: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(key) or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return counts


# ── Triage stage: RAG retrieval ──────────────────────────────────────────────

def _apply_rag_matches(finding: dict, results) -> None:
    """Attach one finding's Upstash matches to its `context` list."""
    for match in results or []:
        metadata = match.metadata or {}
        finding["context"].append({
            "vuln_id": match.id,
            "pair_id": metadata.get("pair_id"),
            "score": round(float(getattr(match, "score", 0) or 0), 4),
            "similar_vulnerable_code": metadata.get("text", ""),
            "vuln_type": metadata.get("vuln_type"),
            "framework": metadata.get("framework"),
            "language": metadata.get("language"),
            "cwe": metadata.get("cwe"),
            "owasp": metadata.get("owasp"),
        })


async def retrieve_context(state: StaticAnalysisState) -> dict:
    """Attach similar known-vulnerable patterns from Upstash to each finding.

    Embeds every merged finding's snippet in a single FastEmbed batch, then runs
    the vector queries concurrently (bounded by `RAG_CONCURRENCY`). Doing this
    one finding at a time made the stage scale linearly with a network round-trip
    per finding, which dominated the whole flow on a large repo.

    Queries are filtered to `type = 'vulnerable'` so triage compares against
    confirmed-bad code.
    """
    findings = state.get("merged_findings") or []
    print(f"--- [retrieve_context] RAG lookup for {len(findings)} finding(s) ---")

    if not findings:
        return {"merged_findings": findings}

    if not upstash_index:
        print("--- [retrieve_context] Upstash client unavailable — skipping RAG ---")
        return {"merged_findings": findings,
                "errors": ["retrieve_context: Upstash Vector not configured, triage runs without RAG context"]}

    # Only findings that actually have text to match on.
    targets = [
        (finding, finding.get("raw_snippet") or finding.get("description") or "")
        for finding in findings
    ]
    targets = [(finding, text) for finding, text in targets if text]
    if not targets:
        return {"merged_findings": findings}

    try:
        vectors = await asyncio.to_thread(_embed_many, [text for _, text in targets])
    except Exception as exc:
        print(f"--- [retrieve_context] embedding failed: {exc} ---")
        return {"merged_findings": findings,
                "errors": [f"retrieve_context: embedding model unavailable ({exc})"]}

    semaphore = asyncio.Semaphore(RAG_CONCURRENCY)

    async def query_one(finding: dict, vector: list[float]):
        async with semaphore:
            try:
                return await asyncio.to_thread(
                    upstash_index.query,
                    vector=vector,
                    top_k=2,
                    include_metadata=True,
                    filter="type = 'vulnerable'",
                )
            except Exception as exc:
                print(f"--- [retrieve_context] query failed for {finding.get('rule_id')}: {exc} ---")
                return None

    results = await asyncio.gather(*[
        query_one(finding, vector) for (finding, _), vector in zip(targets, vectors)
    ])

    matched = 0
    for (finding, _), result in zip(targets, results):
        _apply_rag_matches(finding, result)
        if finding["context"]:
            matched += 1

    print(f"--- [retrieve_context] {matched}/{len(findings)} finding(s) matched a known pattern ---")
    return {"merged_findings": findings}


# ── Triage stage: per-finding LLM classification loop ───────────────────────

def _taint_path_block(taint_path: list[dict]) -> str:
    """Render a taint path for the prompt as an explicit source → sink chain."""
    lines = []
    for step in taint_path:
        lines.append(
            f"  {step.get('step')}. [{step.get('role', 'step').upper()}] "
            f"{step.get('file')}:{step.get('line')} — {step.get('snippet') or step.get('message') or ''}"
        )
        if step.get("message") and step.get("snippet"):
            lines.append(f"        note: {step['message']}")
    return "\n".join(lines)


def _build_triage_prompt(finding: dict) -> str:
    prompt = f"""You are a senior application security engineer triaging static analysis results.
Decide whether this finding is a genuine, exploitable vulnerability ("confirmed")
or a non-issue ("false_positive").

FINDING
  Reported by: {', '.join(finding.get('confirmed_by') or [finding.get('tool_source', 'unknown')])}
  Rule:        {finding.get('rule_id')}
  Category:    {finding.get('category')}
  Location:    {finding.get('file')}:{finding.get('line')}
  Severity:    {finding.get('severity')} (as reported by the tool)
  Message:     {finding.get('description')}

CODE
```
{finding.get('raw_snippet') or '(no snippet captured)'}
```
"""

    if finding.get("multi_tool_confirmed"):
        prompt += f"""
CORROBORATION
  {len(finding['confirmed_by'])} independent tools flagged this same location:
  {', '.join(finding['confirmed_by'])}.
  Agreement between independent engines meaningfully lowers the chance of a false positive.
"""

    taint_path = finding.get("taint_path")
    if taint_path:
        prompt += f"""
CODEQL TAINT PATH — STRONGEST AVAILABLE EVIDENCE
CodeQL traced untrusted data all the way from its entry point to a dangerous sink:

{_taint_path_block(taint_path)}

A complete taint path is proof of *reachability*, not merely a suspicious-looking
pattern: attacker-controlled input demonstrably arrives at the sink. Weigh this
strongly toward "confirmed", and in your reason explicitly name the source
({taint_path[0].get('file')}:{taint_path[0].get('line')}) and the sink
({taint_path[-1].get('file')}:{taint_path[-1].get('line')}) and explain what flows between them.
Only rule it out if you can point to concrete sanitization visible in the path itself.
"""

    if finding.get("context"):
        prompt += "\nKNOWN-VULNERABLE PATTERNS RETRIEVED FROM THE KNOWLEDGE BASE\n"
        for ctx in finding["context"][:2]:
            prompt += f"""  · {ctx.get('vuln_type')} ({ctx.get('framework')}, {ctx.get('cwe')}) — similarity {ctx.get('score')}
    ```
    {ctx.get('similar_vulnerable_code')}
    ```
"""

    if finding.get("package"):
        prompt += f"""
DEPENDENCY CONTEXT
  Package {finding['package']} {finding.get('package_version')} is affected.
  Fixed in: {', '.join(finding.get('fixed_versions') or []) or 'no fixed version published'}.
  Judge reachability and whether an upgrade path exists.
"""

    prompt += """
Respond with a verdict of exactly "confirmed" or "false_positive", a final
severity, your confidence, and a reason of 2-4 sentences that cites the specific
evidence you relied on.
"""
    return prompt


def _triage_limit(state: StaticAnalysisState) -> int:
    """How many merged findings this run will actually triage."""
    findings = state.get("merged_findings") or []
    cap = state.get("max_triage") or len(findings)
    return min(len(findings), max(0, cap))


def _fallback_verdict(exc: Exception) -> dict:
    """Fail open: retain the finding for manual review rather than dropping it.

    Silently discarding a finding because the triage model was unreachable would
    hide a potentially real vulnerability, so an unavailable LLM produces a
    low-confidence "confirmed" instead.
    """
    return {
        "verdict": "confirmed",
        "triage_reason": (
            f"Automatic triage was unavailable ({exc}). Retained as a confirmed finding "
            "for manual review rather than discarded."
        ),
        "triage_confidence": "low",
        "final_severity": None,
    }


async def _triage_one(finding: dict) -> dict:
    """Ask the LLM for one verdict. Never raises — failures fail open."""
    try:
        decision = await _get_triage_llm().ainvoke(_build_triage_prompt(finding))
        severity = str(decision.severity).lower().strip()
        return {
            "verdict": "confirmed" if str(decision.verdict).lower().strip() != "false_positive"
                       else "false_positive",
            "triage_reason": decision.reason,
            "triage_confidence": str(decision.confidence).lower().strip(),
            "final_severity": severity if severity in SEVERITY_RANK else None,
        }
    except Exception as exc:
        print(f"--- [triage] LLM triage failed for {finding.get('rule_id')}: {exc} ---")
        return _fallback_verdict(exc)


async def triage(state: StaticAnalysisState) -> dict:
    """Classify one merged finding as confirmed or a false positive.

    Yields a single finding per iteration so the graph loops visibly — each pass
    streams its own state update and the UI can render triage progress. The LLM
    calls themselves are *not* serialized to match: a cache miss fetches the next
    `TRIAGE_PREFETCH` verdicts concurrently, so a 30-finding scan costs 5 rounds
    of latency rather than 30 while still reporting progress one at a time.
    """
    findings = state.get("merged_findings") or []
    index = state.get("triage_index", 0)
    finding = dict(findings[index])
    cache = dict(state.get("triage_cache") or {})

    label = f"{finding.get('file')}:{finding.get('line')} [{finding.get('category')}]"
    print(f"--- [triage] {index + 1}/{len(findings)} — {label} ---")

    if str(index) not in cache:
        limit = _triage_limit(state)
        window = [
            i for i in range(index, min(index + TRIAGE_PREFETCH, limit))
            if str(i) not in cache
        ]
        print(f"--- [triage] prefetching {len(window)} verdict(s) concurrently ---")
        verdicts = await asyncio.gather(*[_triage_one(findings[i]) for i in window])
        cache.update({str(i): verdict for i, verdict in zip(window, verdicts)})

    # Pop rather than read: a consumed verdict must not keep riding along on every
    # subsequent state update streamed to the client.
    decision = cache.pop(str(index), None) or _fallback_verdict(RuntimeError("no verdict produced"))

    finding["verdict"] = decision["verdict"]
    finding["triage_reason"] = decision["triage_reason"]
    finding["triage_confidence"] = decision["triage_confidence"]
    finding["final_severity"] = decision["final_severity"] or finding.get("severity", "medium")

    return {
        "current_finding": finding,
        "triage_index": index + 1,
        "triage_progress": {"done": index + 1, "total": _triage_limit(state)},
        "triage_cache": cache,
    }


def route_verdict(state: StaticAnalysisState) -> str:
    """Conditional edge: send the triaged finding down the confirm or discard branch."""
    finding = state.get("current_finding") or {}
    return "discard" if finding.get("verdict") == "false_positive" else "confirm"


def _persist_finding(finding: dict, state: StaticAnalysisState, is_false_positive: bool) -> int | None:
    """Write one triaged finding to NeonDB, returning its row id.

    Returns None without touching the database when the run has no scan row —
    that is the CLI's `--no-db` mode, where opening a connection per finding
    would add a network round-trip for a row nobody asked for.
    """
    if not state.get("scan_id"):
        return None

    db = SessionLocal()
    try:
        taint_path = finding.get("taint_path")
        evidence = finding.get("raw_snippet") or ""
        if taint_path:
            evidence += "\n\nTaint path:\n" + _taint_path_block(taint_path)

        row = Finding(
            scan_id=state.get("scan_id"),
            flow_run_id=state.get("flow_run_id"),
            issue_title=f"{finding.get('category')}: {finding.get('rule_id')}",
            description=f"{finding.get('description')}\n\nTriage ({finding.get('triage_confidence')} "
                        f"confidence): {finding.get('triage_reason')}",
            severity=finding.get("final_severity", "medium"),
            category=finding.get("category"),
            endpoint_or_file=f"{finding.get('file')}:{finding.get('line')}",
            evidence=evidence[:8000],
            is_false_positive=is_false_positive,
            tool_source=finding.get("tool_source"),
            rule_id=finding.get("rule_id"),
            multi_tool_confirmed=bool(finding.get("multi_tool_confirmed")),
            taint_path=taint_path,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    except Exception as exc:
        db.rollback()
        print(f"--- [persist] Failed to write finding to NeonDB: {exc} ---")
        return None
    finally:
        db.close()


def confirm_finding(state: StaticAnalysisState) -> dict:
    """Keep a confirmed finding, with the LLM's reasoning, and persist it."""
    finding = dict(state.get("current_finding") or {})
    finding["db_id"] = _persist_finding(finding, state, is_false_positive=False)
    evidence = "taint path" if finding.get("taint_path") else \
               "multi-tool agreement" if finding.get("multi_tool_confirmed") else "single-tool pattern"
    print(f"--- [confirm] {finding.get('file')}:{finding.get('line')} "
          f"→ {finding.get('final_severity')} (evidence: {evidence}) ---")
    return {"triaged_findings": [finding]}


def discard_finding(state: StaticAnalysisState) -> dict:
    """Rule out a finding, keeping the LLM's reasoning for the audit trail."""
    finding = dict(state.get("current_finding") or {})
    finding["db_id"] = _persist_finding(finding, state, is_false_positive=True)
    print(f"--- [discard] {finding.get('file')}:{finding.get('line')} ruled out ---")
    return {"false_positives": [finding]}


def route_triage_loop(state: StaticAnalysisState) -> str:
    """Conditional edge: triage the next finding, or move on to fix generation."""
    return "triage" if state.get("triage_index", 0) < _triage_limit(state) else "fix_generator"


def route_triage_start(state: StaticAnalysisState) -> str:
    """Conditional edge: enter the triage loop, or skip straight to the report.

    Checks the effective limit, not just whether findings exist, so `max_triage=0`
    skips the loop instead of entering it and indexing past the end.
    """
    return "triage" if _triage_limit(state) > 0 else "report_builder"


# ── Fix generation ───────────────────────────────────────────────────────────

def _retrieve_safe_example(finding: dict) -> dict | None:
    """Fetch the closest known-good (fixed) example for a confirmed finding.

    Prefers the exact counterpart of the vulnerable pattern that matched during
    retrieval (`fix_for = <pair_id>`), and otherwise falls back to the nearest
    safe pattern in the same category.
    """
    if not upstash_index:
        return None

    # Exact counterpart of the matched vulnerable pattern.
    for ctx in finding.get("context", [])[:2]:
        pair_id = ctx.get("pair_id") or ctx.get("vuln_id")
        if not pair_id:
            continue
        try:
            results = upstash_index.query(
                vector=_embed(finding.get("raw_snippet") or finding.get("description") or "fix"),
                top_k=1,
                include_metadata=True,
                filter=f"type = 'safe' AND fix_for = '{pair_id}'",
            )
            if results:
                metadata = results[0].metadata or {}
                return {"code": metadata.get("text", ""), "framework": metadata.get("framework"),
                        "vuln_type": metadata.get("vuln_type"), "match": "paired"}
        except Exception as exc:
            print(f"--- [fix_generator] paired safe-pattern lookup failed: {exc} ---")

    # Nearest safe example in the same category.
    category = (finding.get("category") or "").replace("'", "''")
    if not category or category == "Other":
        return None
    try:
        results = upstash_index.query(
            vector=_embed(finding.get("raw_snippet") or finding.get("description") or "fix"),
            top_k=1,
            include_metadata=True,
            filter=f"type = 'safe' AND vuln_type = '{category}'",
        )
        if results:
            metadata = results[0].metadata or {}
            return {"code": metadata.get("text", ""), "framework": metadata.get("framework"),
                    "vuln_type": metadata.get("vuln_type"), "match": "category"}
    except Exception as exc:
        print(f"--- [fix_generator] category safe-pattern lookup failed: {exc} ---")
    return None


def _build_fix_prompt(finding: dict, safe_example: dict | None) -> str:
    """Prompt for one remediation, grounded in a retrieved safe pattern if any."""
    prompt = f"""You are a senior application security engineer writing a patch.

VULNERABILITY
  File:     {finding.get('file')}:{finding.get('line')}
  Category: {finding.get('category')}
  Severity: {finding.get('final_severity')}
  Rule:     {finding.get('rule_id')}
  Detail:   {finding.get('description')}

VULNERABLE CODE
```
{finding.get('raw_snippet') or '(no snippet captured)'}
```

TRIAGE REASONING
{finding.get('triage_reason')}
"""

    if finding.get("taint_path"):
        prompt += f"""
TAINT PATH TO CLOSE
{_taint_path_block(finding['taint_path'])}

Your fix must break this flow — sanitize or parameterize at the sink, or validate
at the source. Say which step of the path your change neutralizes.
"""

    if safe_example and safe_example.get("code"):
        prompt += f"""
VERIFIED SAFE PATTERN FOR THIS CATEGORY ({safe_example.get('framework')})
```
{safe_example['code']}
```
Ground your patch in this idiom, adapted to the surrounding code.
"""

    if finding.get("package"):
        prompt += f"""
This is a dependency vulnerability. The fix is a version bump of
{finding['package']} from {finding.get('package_version')} to
{', '.join(finding.get('fixed_versions') or []) or 'a patched release'}.
Show the manifest change and note any breaking-change risk.
"""

    prompt += "\nReturn the corrected code and an explanation of why it closes the vulnerability."
    return prompt


async def fix_generator(state: StaticAnalysisState) -> dict:
    """Generate a grounded remediation diff for every confirmed finding.

    All patches are generated concurrently (bounded by `FIX_CONCURRENCY`) and
    committed in one transaction. Generating them one at a time made this stage
    cost one LLM round-trip plus one database round-trip per confirmed finding,
    which on a repo with a dozen real issues was the single slowest stage in the
    flow after CodeQL.
    """
    confirmed = state.get("triaged_findings") or []
    print(f"--- [fix_generator] Generating fixes for {len(confirmed)} confirmed finding(s) ---")

    if not confirmed:
        return {"fixes": []}

    llm = _get_fix_llm()
    semaphore = asyncio.Semaphore(FIX_CONCURRENCY)

    async def generate(finding: dict) -> dict | str:
        """Return a fix record, or an error string for the report's error list."""
        try:
            # Retrieval is two blocking HTTP calls — keep it off the event loop.
            safe_example = await asyncio.to_thread(_retrieve_safe_example, finding)
        except Exception as exc:
            print(f"--- [fix_generator] safe-pattern lookup failed: {exc} ---")
            safe_example = None

        async with semaphore:
            try:
                result = await llm.ainvoke(_build_fix_prompt(finding, safe_example))
            except Exception as exc:
                print(f"--- [fix_generator] Fix generation failed for {finding.get('rule_id')}: {exc} ---")
                return f"fix_generator: {finding.get('rule_id')} — {exc}"

        return {
            "finding_id": finding.get("db_id"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "category": finding.get("category"),
            "severity": finding.get("final_severity"),
            "rule_id": finding.get("rule_id"),
            "tool_source": finding.get("tool_source"),
            "diff_text": result.diff_text,
            "explanation": result.explanation,
            "grounded_in": safe_example.get("match") if safe_example else "none",
            "safe_reference": safe_example.get("code") if safe_example else None,
        }

    outcomes = await asyncio.gather(*[generate(finding) for finding in confirmed])
    fixes = [outcome for outcome in outcomes if isinstance(outcome, dict)]
    errors = [outcome for outcome in outcomes if isinstance(outcome, str)]

    # One transaction for every fix rather than a session per finding.
    persistable = [fix for fix in fixes if fix.get("finding_id")]
    if persistable:
        db = SessionLocal()
        try:
            db.add_all([
                Fix(finding_id=fix["finding_id"],
                    diff_text=fix["diff_text"],
                    explanation=fix["explanation"])
                for fix in persistable
            ])
            db.commit()
        except Exception as exc:
            db.rollback()
            print(f"--- [fix_generator] Failed to persist fixes: {exc} ---")
        finally:
            db.close()

    print(f"--- [fix_generator] Produced {len(fixes)} fix(es) ---")
    return {"fixes": fixes, "errors": errors}


# ── Report ───────────────────────────────────────────────────────────────────

def report_builder(state: StaticAnalysisState) -> dict:
    """Assemble the final summary and finalize the NeonDB scan/flow rows.

    Confirmed findings sourced from CodeQL keep their full taint path in the
    report output — the source function, the intermediate hops, and the
    dangerous sink — because that chain is the clearest demonstration of a real,
    reachable vulnerability rather than a pattern match.
    """
    print("--- [report_builder] Assembling static analysis report ---")

    merged = state.get("merged_findings") or []
    confirmed = state.get("triaged_findings") or []
    ruled_out = state.get("false_positives") or []
    fixes = state.get("fixes") or []
    tool_status = state.get("tool_status") or {}
    merge_stats = state.get("merge_stats") or {}

    findings_per_tool = {
        tool: {
            "raw": (merge_stats.get("raw_per_tool") or {}).get(tool, 0),
            "ran": bool(status.get("ok")),
            "used_sample": bool(status.get("used_sample")),
            "duration_s": status.get("duration_s", 0),
            "note": status.get("note", ""),
        }
        for tool, status in tool_status.items()
    }

    # Attribute merged findings back to every tool that reported them.
    attribution: dict[str, int] = {}
    for finding in merged:
        for tool in finding.get("confirmed_by") or []:
            attribution[tool] = attribution.get(tool, 0) + 1
    for tool, entry in findings_per_tool.items():
        entry["after_merge"] = attribution.get(tool, 0)

    triaged_count = len(confirmed) + len(ruled_out)
    not_triaged = max(0, len(merged) - triaged_count)

    # ── CodeQL taint-path evidence for confirmed findings ──
    taint_evidence = [
        {
            "rule_id": finding.get("rule_id"),
            "category": finding.get("category"),
            "severity": finding.get("final_severity"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "source": finding["taint_path"][0],
            "sink": finding["taint_path"][-1],
            "intermediate_steps": finding["taint_path"][1:-1],
            "taint_path": finding["taint_path"],
            "step_count": len(finding["taint_path"]),
            "chain": " → ".join(
                f"{step.get('file')}:{step.get('line')}" for step in finding["taint_path"]
            ),
            "triage_reason": finding.get("triage_reason"),
        }
        for finding in confirmed
        if finding.get("taint_path")
    ]

    source_repo = state.get("source_repo") or ""
    report = {
        # For a cloned repo, report the original URL rather than the temp path —
        # the local clone dir is an implementation detail the user never chose.
        "target_path": source_repo or state.get("target_path"),
        "source_repo": source_repo,
        "scan_id": state.get("scan_id"),
        "flow_run_id": state.get("flow_run_id"),
        "scan_timestamp": datetime.now().isoformat(),
        "codeql_language": state.get("codeql_language"),

        # Findings per tool, plus how many survived the merge.
        "findings_per_tool": findings_per_tool,
        "tool_status": tool_status,

        # Merge / dedup accounting.
        "total_raw_findings": merge_stats.get("total_raw", 0),
        "total_after_merge": merge_stats.get("total_after_dedup", len(merged)),
        "duplicates_removed": merge_stats.get("duplicates_removed", 0),
        "multi_tool_confirmed_count": merge_stats.get("multi_tool_confirmed", 0),
        "with_taint_path_count": merge_stats.get("with_taint_path", 0),

        # Triage outcome.
        "confirmed_count": len(confirmed),
        "ruled_out_count": len(ruled_out),
        "not_triaged_count": not_triaged,
        "fixes_count": len(fixes),

        "severity_breakdown": _count_by(confirmed, "final_severity"),
        "category_breakdown": _count_by(confirmed, "category"),
        "merged_severity_breakdown": merge_stats.get("severity_breakdown", {}),
        "merged_category_breakdown": merge_stats.get("category_breakdown", {}),

        # Full detail for the UI.
        "confirmed_findings": confirmed,
        "ruled_out_findings": ruled_out,
        "safe_patterns": state.get("safe_patterns") or [],
        "fixes": fixes,

        # Strongest evidence, surfaced on its own for the report header.
        "codeql_taint_evidence": taint_evidence,

        "summary": _summary_text(state, confirmed, ruled_out, taint_evidence, merge_stats),
        "errors": state.get("errors") or [],
    }

    # ── Finalize the NeonDB scan + flow_run rows ──
    # Skipped entirely for runs with no scan row (the CLI's --no-db mode).
    if state.get("scan_id") or state.get("flow_run_id"):
        db = SessionLocal()
        try:
            flow = db.get(FlowRun, state.get("flow_run_id")) if state.get("flow_run_id") else None
            if flow:
                flow.status = "completed"
            scan = db.get(Scan, state.get("scan_id")) if state.get("scan_id") else None
            if scan:
                scan.status = "completed"
                scan.finished_at = datetime.utcnow()
            db.commit()
        except Exception as exc:
            db.rollback()
            print(f"--- [report_builder] Failed to finalize scan rows: {exc} ---")
        finally:
            db.close()

    print(f"--- [report_builder] {report['total_after_merge']} unique findings · "
          f"{report['confirmed_count']} confirmed · {report['ruled_out_count']} ruled out · "
          f"{len(taint_evidence)} with taint paths ---")

    # Delete the shallow clone now that every stage has finished reading it.
    clone_dir = state.get("cloned_repo_dir")
    if clone_dir:
        tools.cleanup_clone(clone_dir)
        print(f"--- [report_builder] Removed temp clone {clone_dir} ---")

    return {"static_report": report}


def _summary_text(state: StaticAnalysisState, confirmed: list[dict], ruled_out: list[dict],
                  taint_evidence: list[dict], merge_stats: dict) -> str:
    """One-paragraph plain-language summary of the scan."""
    tools_reporting = merge_stats.get("tools_reporting", 0)
    scanned = state.get("source_repo") or state.get("target_path")
    parts = [
        f"Scanned {scanned} with five independent engines "
        f"({tools_reporting} reported findings). "
        f"{merge_stats.get('total_raw', 0)} raw findings merged down to "
        f"{merge_stats.get('total_after_dedup', 0)} unique issues "
        f"({merge_stats.get('duplicates_removed', 0)} duplicates removed, "
        f"{merge_stats.get('multi_tool_confirmed', 0)} corroborated by more than one tool)."
    ]
    parts.append(
        f"LLM triage confirmed {len(confirmed)} and ruled out {len(ruled_out)} as false positives."
    )
    if taint_evidence:
        top = taint_evidence[0]
        parts.append(
            f"{len(taint_evidence)} confirmed finding(s) carry a complete CodeQL taint path — "
            f"the strongest available evidence of reachability — including "
            f"{top['category']} flowing {top['chain']}."
        )
    if confirmed:
        worst = max(confirmed, key=lambda f: SEVERITY_RANK.get(f.get("final_severity", "low"), 0))
        parts.append(
            f"Highest-severity issue: {worst.get('final_severity', 'unknown').upper()} "
            f"{worst.get('category')} at {worst.get('file')}:{worst.get('line')}."
        )
    else:
        parts.append("No confirmed vulnerabilities remain after triage.")
    return " ".join(parts)
