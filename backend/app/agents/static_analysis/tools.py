"""Scanner adapters for the Static Analysis flow.

Each `run_*` function shells out to one security tool, parses its native
output format, and returns findings in the flow's common schema:

    {
        "tool_source":  "semgrep" | "bearer" | "osv-scanner" | "gitleaks" | "codeql",
        "file":         repo-relative path,
        "line":         int,
        "severity":     "critical" | "high" | "medium" | "low" | "info",
        "rule_id":      the tool's own rule identifier,
        "category":     canonical vulnerability category (matches Upstash `vuln_type`),
        "description":  human-readable explanation,
        "raw_snippet":  the offending source text,
        "taint_path":   list of taint steps (CodeQL only, else None),
    }

Every runner is failure-tolerant: a missing binary, a non-zero exit, or
unparsable output produces an empty finding list plus a status record rather
than raising, so one broken tool never takes the graph down. When a tool is
unavailable the runner falls back to a small representative sample so the
downstream RAG → triage → fix stages still have data to operate on.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# Per-tool wall-clock budgets. CodeQL gets a much larger one because it has to
# build a database before it can run a single query.
FAST_TOOL_TIMEOUT = 300      # semgrep / bearer / osv-scanner / gitleaks
CODEQL_DB_TIMEOUT = 900      # database create
CODEQL_ANALYZE_TIMEOUT = 900  # database analyze

MAX_SNIPPET_CHARS = 600

# Directories that hold third-party or generated code. Scanning them is the
# single biggest waste of time in a repo scan — `node_modules` alone can be
# larger than the source tree by an order of magnitude, and nothing in it is
# actionable, since a dependency CVE is OSV-Scanner's job rather than a SAST
# rule's. Every runner that supports an exclude flag is given this list.
EXCLUDE_DIRS = (
    "node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build",
    ".next", "out", "coverage", "vendor", "site-packages", "target",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".turbo", ".cache",
)

# Skip generated bundles and minified output — huge single-line files that cost
# a lot to parse and produce findings nobody can act on.
EXCLUDE_GLOBS = ("*.min.js", "*.min.css", "*.map", "*.lock", "*.bundle.js")

# Semgrep's rule source. "auto" resolves the registry ruleset for each detected
# language, which is the broadest option but re-resolves over the network on a
# cold cache. Pin a lighter ruleset (e.g. "p/security-audit") via the env var for
# a faster pass.
SEMGREP_CONFIG = os.environ.get("SECURA_SEMGREP_CONFIG", "auto")

# Files above this size are almost always generated; Semgrep skips them rather
# than spending its budget there.
SEMGREP_MAX_TARGET_BYTES = 1_500_000


def _cpu_jobs() -> int:
    """Worker count for tools that parallelize across files."""
    return max(1, min(8, (os.cpu_count() or 2)))


# ── Category normalization ───────────────────────────────────────────────────
# The canonical category strings mirror the `vuln_type` values seeded into
# Upstash Vector, so a merged finding's category can be used directly as a
# metadata filter when retrieving safe (fixed) examples.

CWE_CATEGORIES: dict[str, str] = {
    "89": "SQL Injection",
    "564": "SQL Injection",
    "943": "NoSQL Injection",
    "79": "Cross-Site Scripting",
    "80": "Cross-Site Scripting",
    "116": "Cross-Site Scripting",
    "22": "Path Traversal",
    "23": "Path Traversal",
    "36": "Path Traversal",
    "78": "Command Injection",
    "77": "Command Injection",
    "88": "Command Injection",
    "502": "Insecure Deserialization",
    "94": "Server-Side Template Injection",
    "95": "Server-Side Template Injection",
    "1336": "Server-Side Template Injection",
    "798": "Hardcoded Secret",
    "259": "Hardcoded Secret",
    "321": "Hardcoded Secret",
    "347": "Broken Authentication",
    "256": "Broken Authentication",
    "287": "Broken Authentication",
    "306": "Broken Authentication",
    "918": "Server-Side Request Forgery",
    "327": "Weak Cryptography",
    "328": "Weak Cryptography",
    "326": "Weak Cryptography",
    "330": "Weak Cryptography",
    "338": "Weak Cryptography",
    "532": "Sensitive Data Exposure",
    "200": "Sensitive Data Exposure",
    "209": "Sensitive Data Exposure",
    "942": "CORS Misconfiguration",
    "346": "CORS Misconfiguration",
    "611": "XML External Entity",
    "776": "XML External Entity",
    "434": "Unrestricted File Upload",
    "90": "LDAP Injection",
    "915": "Mass Assignment",
    "362": "Race Condition",
    "367": "Race Condition",
    "1104": "Vulnerable Dependency",
    "937": "Vulnerable Dependency",
    "352": "Cross-Site Request Forgery",
    "601": "Open Redirect",
    "1333": "Denial of Service",
    "400": "Denial of Service",
    "20": "Improper Input Validation",
}

# Ordered keyword rules — first match wins, so put the specific ones first.
KEYWORD_CATEGORIES: list[tuple[str, str]] = [
    (r"nosql|mongo.*inject", "NoSQL Injection"),
    (r"sql.?inject|tainted[-_ ]sql|sqli", "SQL Injection"),
    (r"\bxss\b|cross.?site.?script|innerhtml|dangerouslysetinnerhtml", "Cross-Site Scripting"),
    (r"path.?travers|zip.?slip|directory.?travers|tainted.?path", "Path Traversal"),
    (r"command.?inject|os.?command|shell.?inject|child_process|exec", "Command Injection"),
    (r"deserializ|pickle|unmarshal|yaml\.load", "Insecure Deserialization"),
    (r"template.?inject|\bssti\b", "Server-Side Template Injection"),
    (r"hard.?cod|secret|api.?key|credential|private.?key|token", "Hardcoded Secret"),
    (r"\bssrf\b|server.?side.?request", "Server-Side Request Forgery"),
    (r"\bjwt\b|auth|password|session.?fixation", "Broken Authentication"),
    (r"\bmd5\b|\bsha1\b|weak.?(crypto|cipher|hash|random)|insecure.?random|\bdes\b|\brc4\b", "Weak Cryptography"),
    (r"\bcors\b|access.?control.?allow.?origin", "CORS Misconfiguration"),
    (r"\bxxe\b|external.?entity|xml.?entity", "XML External Entity"),
    (r"file.?upload|unrestricted.?upload", "Unrestricted File Upload"),
    (r"ldap.?inject", "LDAP Injection"),
    (r"mass.?assign|prototype.?pollut", "Mass Assignment"),
    (r"race.?condition|toctou", "Race Condition"),
    (r"\bcsrf\b|cross.?site.?request", "Cross-Site Request Forgery"),
    (r"open.?redirect|unvalidated.?redirect", "Open Redirect"),
    (r"log.*(leak|sensitive)|sensitive.?data|information.?(leak|exposure|disclos)", "Sensitive Data Exposure"),
    (r"regex.?denial|redos|denial.?of.?service", "Denial of Service"),
    (r"vulnerab|advisory|\bcve-|\bghsa-", "Vulnerable Dependency"),
]


def categorize(rule_id: str = "", description: str = "", cwe_ids: list | None = None) -> str:
    """Map a tool-native finding onto one canonical vulnerability category."""
    for raw in cwe_ids or []:
        # CWE references arrive as "CWE-89", "89", or "CWE-89: Improper Neutralization…".
        match = re.search(r"(\d+)", str(raw))
        if match and match.group(1) in CWE_CATEGORIES:
            return CWE_CATEGORIES[match.group(1)]

    haystack = f"{rule_id} {description}".lower()
    for pattern, category in KEYWORD_CATEGORIES:
        if re.search(pattern, haystack):
            return category
    return "Other"


# ── Shared helpers ───────────────────────────────────────────────────────────

def _rel_path(path: str, root: str) -> str:
    """Make `path` repo-relative with forward slashes (stable across platforms)."""
    if not path:
        return "unknown"
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    except (ValueError, OSError):
        # Different drives on Windows, or a malformed path — keep the original.
        rel = path
    return rel.replace("\\", "/").lstrip("./") or os.path.basename(path)


def _clip(text, limit: int = MAX_SNIPPET_CHARS) -> str:
    """Trim a snippet to a sane length for prompts, the UI, and the DB."""
    if text is None:
        return ""
    text = str(text).strip()
    return text if len(text) <= limit else text[:limit] + " …"


def _redact(text: str) -> str:
    """Mask anything that looks like a live secret before it leaves this module.

    Gitleaks findings legitimately contain real credentials. Those must never
    reach the LLM prompt, the report JSON, or the database — only enough of the
    value to let a developer locate it.
    """
    if not text:
        return ""

    def mask(match: re.Match) -> str:
        value = match.group(0)
        return value[:4] + "*" * max(4, len(value) - 8) + value[-4:] if len(value) > 12 else "*" * len(value)

    # Long unbroken alphanumeric runs are the usual shape of keys and tokens.
    return re.sub(r"[A-Za-z0-9_\-/+=]{16,}", mask, text)


def _run(cmd: list[str], timeout: int, cwd: str | None = None) -> tuple[int, str, str]:
    """Run a command, returning (returncode, stdout, stderr).

    Returns a synthetic returncode for the failure cases a caller cares about:
      -1  the binary was not found
      -2  the command exceeded its timeout
      -3  anything else went wrong launching it
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found on PATH"
    except subprocess.TimeoutExpired:
        return -2, "", f"{cmd[0]} exceeded its {timeout}s budget"
    except Exception as exc:  # pragma: no cover - defensive
        return -3, "", f"{cmd[0]} failed to start: {exc}"


def _which(name: str) -> str | None:
    """Locate a tool on PATH, also checking the active venv's script directory."""
    found = shutil.which(name)
    if found:
        return found
    venv_scripts = os.path.dirname(sys.executable)
    for candidate in (name, f"{name}.exe", f"{name}.cmd", f"{name}.bat"):
        path = os.path.join(venv_scripts, candidate)
        if os.path.isfile(path):
            return path
    return None


# ── Remote repository support ────────────────────────────────────────────────
# A SAST scan can target a local path or a public Git repository. When the
# target looks like a repo URL we shallow-clone it to a temp directory, scan the
# clone, and delete it afterwards — so the same five-tool pipeline works on a
# GitHub URL with no other change.
GIT_URL_RE = re.compile(
    r"^(?:https?://|git@|ssh://|git://)"        # scheme
    r"[\w.@:/\-~]+?"                             # host + path
    r"(?:\.git)?/?$",                            # optional .git suffix
    re.IGNORECASE,
)
# Shorthand like "owner/repo" (GitHub) — no scheme, exactly one slash, no spaces.
GIT_SHORTHAND_RE = re.compile(r"^[\w.\-]+/[\w.\-]+$")

# Cap the clone so a hostile or accidentally-huge repo can't fill the disk.
CLONE_TIMEOUT = 300


def is_git_url(target: str) -> bool:
    """True when `target` should be treated as a remote repo rather than a path.

    Recognizes full clone URLs (https / ssh / git) and GitHub "owner/repo"
    shorthand. An existing local path always wins, so a folder literally named
    like a repo is still scanned in place.
    """
    if not target:
        return False
    t = target.strip()
    if os.path.exists(t):
        return False
    if GIT_URL_RE.match(t):
        return True
    # Shorthand only counts when it isn't a relative path fragment.
    return bool(GIT_SHORTHAND_RE.match(t)) and not t.startswith((".", "/", "~"))


def normalize_git_url(target: str) -> str:
    """Expand "owner/repo" shorthand to a full GitHub HTTPS clone URL."""
    t = target.strip()
    if GIT_SHORTHAND_RE.match(t) and "://" not in t and not t.startswith("git@"):
        return f"https://github.com/{t}.git"
    return t


def clone_repo(url: str) -> tuple[str | None, str]:
    """Shallow-clone a public repo into a temp dir.

    Returns (clone_dir, note). On failure clone_dir is None and the note explains
    why, so the caller can surface it without raising. The caller owns the
    returned directory and must delete it (see `cleanup_clone`).
    """
    git = _which("git")
    if not git:
        return None, "git not found on PATH"

    clone_url = normalize_git_url(url)
    dest = tempfile.mkdtemp(prefix="secura_clone_")
    # --depth 1: history is irrelevant to a SAST scan and dominates clone time.
    # GIT_TERMINAL_PROMPT=0: never block waiting for credentials on a private repo.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        proc = subprocess.run(
            [git, "clone", "--depth", "1", "--single-branch", clone_url, dest],
            capture_output=True, text=True, errors="replace",
            timeout=CLONE_TIMEOUT, env=env, check=False,
        )
    except subprocess.TimeoutExpired:
        cleanup_clone(dest)
        return None, f"clone exceeded its {CLONE_TIMEOUT}s budget"
    except Exception as exc:  # pragma: no cover - defensive
        cleanup_clone(dest)
        return None, f"clone failed to start: {exc}"

    if proc.returncode != 0:
        cleanup_clone(dest)
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else f"git exited {proc.returncode}"
        return None, f"clone failed: {reason}"
    return dest, f"cloned {clone_url}"


def cleanup_clone(path: str | None) -> None:
    """Best-effort removal of a temp clone directory."""
    if not path:
        return
    # Git writes read-only pack files on Windows; clear the bit before deleting.
    def _on_error(func, target, _exc):  # pragma: no cover - platform detail
        try:
            os.chmod(target, 0o700)
            func(target)
        except Exception:
            pass
    try:
        shutil.rmtree(path, onerror=_on_error)
    except Exception:
        pass


def make_status(tool: str, ok: bool, count: int, note: str = "", used_sample: bool = False,
                duration: float = 0.0) -> dict:
    """One row of the per-tool execution report shown in the UI."""
    return {
        "tool": tool,
        "ok": ok,
        "finding_count": count,
        "note": note,
        "used_sample": used_sample,
        "duration_s": round(duration, 2),
    }


_status = make_status  # internal shorthand used throughout this module


def _first_json(text: str):
    """Parse JSON from tool stdout that may be prefixed with log noise."""
    text = (text or "").strip()
    if not text:
        raise ValueError("empty output")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fall back to the first balanced {...} or [...] block in the stream.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError("no JSON object found in output")


# ── 1. Semgrep ───────────────────────────────────────────────────────────────

SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "CRITICAL": "critical"}

SEMGREP_SAMPLE = [
    {
        "tool_source": "semgrep",
        "file": "test_vuln.js",
        "line": 8,
        "severity": "high",
        "rule_id": "javascript.express.security.injection.tainted-sql-string",
        "category": "SQL Injection",
        "description": "Detected untrusted input concatenated into a SQL string. This leads to SQL Injection.",
        "raw_snippet": 'db.query("SELECT * FROM users WHERE id = " + req.params.id, (err, result) => {',
        "taint_path": None,
    },
    {
        "tool_source": "semgrep",
        "file": "test_vuln.js",
        "line": 17,
        "severity": "high",
        "rule_id": "javascript.express.security.injection.command-injection",
        "category": "Command Injection",
        "description": "Detected untrusted input concatenated into a shell command. This leads to Command Injection.",
        "raw_snippet": "exec('ping -c 1 ' + req.body.ip, (err, stdout, stderr) => {",
        "taint_path": None,
    },
]


def parse_semgrep(payload: dict, root: str) -> list[dict]:
    findings = []
    for result in payload.get("results", []) or []:
        extra = result.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        rule_id = result.get("check_id", "semgrep.unknown")
        message = extra.get("message", "") or ""
        findings.append({
            "tool_source": "semgrep",
            "file": _rel_path(result.get("path", ""), root),
            "line": (result.get("start", {}) or {}).get("line", 0),
            "severity": SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "medium"),
            "rule_id": rule_id,
            "category": categorize(rule_id, message, metadata.get("cwe")),
            "description": _clip(message, 800),
            "raw_snippet": _clip(extra.get("lines", "")),
            "taint_path": None,
            "cwe": [str(c) for c in (metadata.get("cwe") or [])][:3],
            "owasp": [str(o) for o in (metadata.get("owasp") or [])][:3],
        })
    return findings


def run_semgrep_tool(root: str) -> tuple[list[dict], dict]:
    """Semgrep SAST: `semgrep --config=<ruleset> --json <root>`.

    Excludes vendored and generated trees, caps target file size, and fans out
    across cores. Telemetry is disabled — it is an extra network round-trip on
    every run for no analytic value here.
    """
    started = time.time()

    args = [
        f"--config={SEMGREP_CONFIG}",
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        f"--jobs={_cpu_jobs()}",
        f"--max-target-bytes={SEMGREP_MAX_TARGET_BYTES}",
    ]
    for pattern in EXCLUDE_DIRS + EXCLUDE_GLOBS:
        args.append(f"--exclude={pattern}")
    args.append(root)

    binary = _which("semgrep")
    if not binary:
        # Semgrep ships as a Python package, so try the module entry point too.
        code, out, err = _run([sys.executable, "-m", "semgrep", *args], FAST_TOOL_TIMEOUT)
    else:
        code, out, err = _run([binary, *args], FAST_TOOL_TIMEOUT)

    elapsed = time.time() - started
    if code in (-1, -2, -3):
        return SEMGREP_SAMPLE, _status("semgrep", False, len(SEMGREP_SAMPLE), err,
                                       used_sample=True, duration=elapsed)
    try:
        findings = parse_semgrep(_first_json(out), root)
    except Exception as exc:
        return SEMGREP_SAMPLE, _status("semgrep", False, len(SEMGREP_SAMPLE),
                                       f"unparsable output: {exc}", used_sample=True, duration=elapsed)

    if not findings:
        return SEMGREP_SAMPLE, _status("semgrep", True, len(SEMGREP_SAMPLE),
                                       "ran clean (no rule matches) — showing sample findings",
                                       used_sample=True, duration=elapsed)
    return findings, _status("semgrep", True, len(findings), "", duration=elapsed)


# ── 2. Bearer ────────────────────────────────────────────────────────────────

BEARER_SEVERITIES = ("critical", "high", "medium", "low", "warning")

BEARER_SAMPLE = [
    {
        "tool_source": "bearer",
        "file": "test_vuln.js",
        "line": 8,
        "severity": "critical",
        "rule_id": "javascript_express_sql_injection",
        "category": "SQL Injection",
        "description": "Unsanitized user input reaches a SQL query construction (CWE-89).",
        "raw_snippet": 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
        "taint_path": None,
    },
    {
        "tool_source": "bearer",
        "file": "test_vuln.js",
        "line": 17,
        "severity": "high",
        "rule_id": "javascript_lang_os_command_injection",
        "category": "Command Injection",
        "description": "User input flows into an OS command execution sink (CWE-78).",
        "raw_snippet": "exec('ping -c 1 ' + req.body.ip)",
        "taint_path": None,
    },
]


def parse_bearer(payload, root: str) -> list[dict]:
    findings = []

    def add(item: dict, severity: str) -> None:
        if not isinstance(item, dict):
            return
        rule_id = item.get("id") or item.get("rule_id") or "bearer.unknown"
        title = item.get("title") or ""
        description = item.get("description") or ""
        cwes = item.get("cwe_ids") or item.get("cwe") or []
        sink = item.get("sink") or {}
        snippet = (
            item.get("code_extract")
            or item.get("snippet")
            or (sink.get("content") if isinstance(sink, dict) else "")
            or ""
        )
        findings.append({
            "tool_source": "bearer",
            "file": _rel_path(item.get("filename") or item.get("full_filename") or "", root),
            "line": item.get("line_number") or (sink.get("start") if isinstance(sink, dict) else 0) or 0,
            "severity": severity if severity in ("critical", "high", "medium", "low") else "low",
            "rule_id": rule_id,
            "category": categorize(rule_id, f"{title} {description}", cwes),
            "description": _clip(f"{title}. {description}".strip(". "), 800),
            "raw_snippet": _clip(snippet),
            "taint_path": None,
            "cwe": [f"CWE-{c}" for c in cwes][:3],
        })

    if isinstance(payload, dict):
        for severity in BEARER_SEVERITIES:
            for item in payload.get(severity, []) or []:
                add(item, "low" if severity == "warning" else severity)
        # Some Bearer versions nest everything under "findings".
        for item in payload.get("findings", []) or []:
            add(item, str(item.get("severity", "medium")).lower())
    elif isinstance(payload, list):
        for item in payload:
            add(item, str((item or {}).get("severity", "medium")).lower())
    return findings


def run_bearer_tool(root: str) -> tuple[list[dict], dict]:
    """Bearer SAST/privacy scanner: `bearer scan <root> --format=json`."""
    started = time.time()
    binary = _which("bearer")
    if not binary:
        return BEARER_SAMPLE, _status("bearer", False, len(BEARER_SAMPLE),
                                      "bearer not found on PATH", used_sample=True,
                                      duration=time.time() - started)

    # Bearer exits 1 when it *finds* something, so the return code is not a
    # failure signal here — only unparsable output is.
    cmd = [binary, "scan", root, "--format=json", "--quiet", "--disable-version-check"]
    for pattern in EXCLUDE_DIRS:
        cmd.append(f"--skip-path={pattern}/**")
    code, out, err = _run(cmd, FAST_TOOL_TIMEOUT)
    elapsed = time.time() - started

    if code in (-2, -3):
        return BEARER_SAMPLE, _status("bearer", False, len(BEARER_SAMPLE), err,
                                      used_sample=True, duration=elapsed)
    try:
        findings = parse_bearer(_first_json(out), root)
    except Exception as exc:
        note = f"unparsable output: {exc}"
        if err:
            note += f" ({_clip(err, 200)})"
        return BEARER_SAMPLE, _status("bearer", False, len(BEARER_SAMPLE), note,
                                      used_sample=True, duration=elapsed)

    if not findings:
        return [], _status("bearer", True, 0, "ran clean — no findings", duration=elapsed)
    return findings, _status("bearer", True, len(findings), "", duration=elapsed)


# ── 3. OSV-Scanner ───────────────────────────────────────────────────────────

OSV_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
                "MEDIUM": "medium", "LOW": "low"}

OSV_SAMPLE = [
    {
        "tool_source": "osv-scanner",
        "file": "package-lock.json",
        "line": 0,
        "severity": "critical",
        "rule_id": "GHSA-35jh-r3h4-6jhm",
        "category": "Vulnerable Dependency",
        "description": "lodash 4.17.15 (npm) — Command Injection in lodash. "
                       "Fixed in 4.17.21. Aliases: CVE-2021-23337.",
        "raw_snippet": '"lodash": "4.17.15"',
        "taint_path": None,
        "package": "lodash",
        "package_version": "4.17.15",
        "ecosystem": "npm",
    },
    {
        "tool_source": "osv-scanner",
        "file": "package-lock.json",
        "line": 0,
        "severity": "high",
        "rule_id": "GHSA-6chw-6frg-f759",
        "category": "Vulnerable Dependency",
        "description": "axios 0.21.1 (npm) — Server-Side Request Forgery via follow-redirects. "
                       "Fixed in 0.21.2. Aliases: CVE-2021-3749.",
        "raw_snippet": '"axios": "0.21.1"',
        "taint_path": None,
        "package": "axios",
        "package_version": "0.21.1",
        "ecosystem": "npm",
    },
]


def _cvss_band(score: str) -> str | None:
    """Map a numeric CVSS base score to a severity band."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low" if value > 0 else None


def parse_osv(payload: dict, root: str) -> list[dict]:
    findings = []
    for result in payload.get("results", []) or []:
        source_path = _rel_path((result.get("source", {}) or {}).get("path", ""), root)
        for pkg_entry in result.get("packages", []) or []:
            pkg = pkg_entry.get("package", {}) or {}
            name = pkg.get("name", "unknown")
            version = pkg.get("version", "?")
            ecosystem = pkg.get("ecosystem", "")

            # `groups` carries the aggregated max_severity per vuln group.
            group_severity: dict[str, str] = {}
            for group in pkg_entry.get("groups", []) or []:
                band = _cvss_band(group.get("max_severity", ""))
                if band:
                    for vuln_id in group.get("ids", []) or []:
                        group_severity[vuln_id] = band

            for vuln in pkg_entry.get("vulnerabilities", []) or []:
                vuln_id = vuln.get("id", "OSV-UNKNOWN")
                db_specific = vuln.get("database_specific", {}) or {}
                severity = (
                    OSV_SEVERITY.get(str(db_specific.get("severity", "")).upper())
                    or group_severity.get(vuln_id)
                    or next(
                        (b for b in (_cvss_band(s.get("score", "")) for s in vuln.get("severity", []) or []) if b),
                        None,
                    )
                    or "medium"
                )
                fixed_versions = sorted({
                    event.get("fixed")
                    for affected in vuln.get("affected", []) or []
                    for rng in affected.get("ranges", []) or []
                    for event in rng.get("events", []) or []
                    if event.get("fixed")
                })
                aliases = [a for a in (vuln.get("aliases") or []) if a != vuln_id][:3]

                description = f"{name} {version} ({ecosystem}) — {vuln.get('summary') or vuln_id}."
                if fixed_versions:
                    description += f" Fixed in {', '.join(fixed_versions[:3])}."
                if aliases:
                    description += f" Aliases: {', '.join(aliases)}."

                findings.append({
                    "tool_source": "osv-scanner",
                    "file": source_path,
                    "line": 0,
                    "severity": severity,
                    "rule_id": vuln_id,
                    "category": "Vulnerable Dependency",
                    "description": _clip(description, 800),
                    "raw_snippet": f'"{name}": "{version}"',
                    "taint_path": None,
                    "package": name,
                    "package_version": version,
                    "ecosystem": ecosystem,
                    "fixed_versions": fixed_versions[:3],
                })
    return findings


def run_osv_tool(root: str) -> tuple[list[dict], dict]:
    """OSV-Scanner dependency audit: `osv-scanner --format=json -r <root>`."""
    started = time.time()
    binary = _which("osv-scanner")
    if not binary:
        return OSV_SAMPLE, _status("osv-scanner", False, len(OSV_SAMPLE),
                                   "osv-scanner not found on PATH", used_sample=True,
                                   duration=time.time() - started)

    # Exit 1 means "vulnerabilities found" — expected, not an error.
    code, out, err = _run([binary, "--format=json", "-r", root], FAST_TOOL_TIMEOUT)
    elapsed = time.time() - started

    if code in (-2, -3):
        return OSV_SAMPLE, _status("osv-scanner", False, len(OSV_SAMPLE), err,
                                   used_sample=True, duration=elapsed)
    try:
        findings = parse_osv(_first_json(out), root)
    except Exception as exc:
        note = f"unparsable output: {exc}"
        if err:
            note += f" ({_clip(err, 200)})"
        return OSV_SAMPLE, _status("osv-scanner", False, len(OSV_SAMPLE), note,
                                   used_sample=True, duration=elapsed)

    if not findings:
        return [], _status("osv-scanner", True, 0,
                           "no known-vulnerable dependencies in any lockfile", duration=elapsed)
    return findings, _status("osv-scanner", True, len(findings), "", duration=elapsed)


# ── 4. Gitleaks ──────────────────────────────────────────────────────────────

# Rules whose hits are effectively always exploitable get bumped to critical.
GITLEAKS_CRITICAL = re.compile(
    r"private.?key|aws|gcp|azure|stripe|github|gitlab|slack.?token|"
    r"database.?url|postgres|mysql|mongodb|jwt|rsa|ssh",
    re.IGNORECASE,
)

GITLEAKS_SAMPLE = [
    {
        "tool_source": "gitleaks",
        "file": ".env.example",
        "line": 12,
        "severity": "critical",
        "rule_id": "generic-api-key",
        "category": "Hardcoded Secret",
        "description": "Hardcoded credential detected by rule 'generic-api-key' (entropy 4.71). "
                       "The value is redacted here — rotate it and move it to a secret manager.",
        "raw_snippet": "OPENROUTER_API_KEY=sk-o****************************9f2c",
        "taint_path": None,
    },
]


def parse_gitleaks(payload, root: str) -> list[dict]:
    findings = []
    for item in payload or []:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("RuleID") or item.get("ruleID") or "gitleaks.unknown"
        description = item.get("Description") or item.get("description") or "Hardcoded secret detected"
        entropy = item.get("Entropy")
        note = f"Hardcoded credential detected by rule '{rule_id}'"
        if isinstance(entropy, (int, float)) and entropy:
            note += f" (entropy {entropy:.2f})"
        note += (f". {description}." if description else ".")
        note += " The value is redacted here — rotate it and move it to a secret manager."

        findings.append({
            "tool_source": "gitleaks",
            "file": _rel_path(item.get("File") or item.get("file") or "", root),
            "line": item.get("StartLine") or item.get("startLine") or 0,
            "severity": "critical" if GITLEAKS_CRITICAL.search(f"{rule_id} {description}") else "high",
            "rule_id": rule_id,
            "category": "Hardcoded Secret",
            "description": _clip(note, 800),
            # Never carry the live credential forward — only a redacted locator.
            "raw_snippet": _clip(_redact(item.get("Match") or ""), 300),
            "taint_path": None,
            "cwe": ["CWE-798"],
        })
    return findings


def run_gitleaks_tool(root: str) -> tuple[list[dict], dict]:
    """Gitleaks secret scan: `gitleaks detect --source=<root> --no-git`.

    Gitleaks only emits JSON to a file, so a temp report path is always passed.
    Newer releases replaced `detect --no-git` with the `dir` subcommand; both
    invocations are attempted.
    """
    started = time.time()
    binary = _which("gitleaks")
    if not binary:
        return GITLEAKS_SAMPLE, _status("gitleaks", False, len(GITLEAKS_SAMPLE),
                                        "gitleaks not found on PATH", used_sample=True,
                                        duration=time.time() - started)

    report_fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-")
    os.close(report_fd)
    try:
        invocations = [
            [binary, "detect", f"--source={root}", "--report-format=json",
             f"--report-path={report_path}", "--no-git", "--exit-code=0"],
            [binary, "dir", root, "--report-format=json",
             f"--report-path={report_path}", "--exit-code=0"],
        ]
        last_err = ""
        for cmd in invocations:
            code, out, err = _run(cmd, FAST_TOOL_TIMEOUT)
            last_err = err or out
            if code in (-1, -2, -3):
                continue
            try:
                with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
                    content = handle.read().strip()
                payload = json.loads(content) if content else []
            except (OSError, json.JSONDecodeError):
                continue

            findings = parse_gitleaks(payload, root)
            elapsed = time.time() - started
            if not findings:
                return [], _status("gitleaks", True, 0, "no secrets detected", duration=elapsed)
            return findings, _status("gitleaks", True, len(findings), "", duration=elapsed)

        return GITLEAKS_SAMPLE, _status("gitleaks", False, len(GITLEAKS_SAMPLE),
                                        _clip(last_err, 200) or "gitleaks produced no report",
                                        used_sample=True, duration=time.time() - started)
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass


# ── 5. CodeQL ────────────────────────────────────────────────────────────────

SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

# Query suite per language. CodeQL packs follow the `codeql/<lang>-queries`
# naming convention; the security-and-quality suite is the broadest standard one.
CODEQL_SUITES = {
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
    "typescript": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
    "python": "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
    "java": "codeql/java-queries:codeql-suites/java-security-and-quality.qls",
    "go": "codeql/go-queries:codeql-suites/go-security-and-quality.qls",
    "ruby": "codeql/ruby-queries:codeql-suites/ruby-security-and-quality.qls",
    "csharp": "codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls",
    "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls",
}

# CodeQL treats TypeScript as part of the JavaScript extractor.
CODEQL_EXTRACTOR = {"typescript": "javascript"}

CODEQL_SAMPLE = [
    {
        "tool_source": "codeql",
        "file": "test_vuln.js",
        "line": 8,
        "severity": "critical",
        "rule_id": "js/sql-injection",
        "category": "SQL Injection",
        "description": "This query string depends on a user-provided value that flows in "
                       "without sanitization, allowing SQL injection.",
        "raw_snippet": '"SELECT * FROM users WHERE id = " + req.params.id',
        "taint_path": [
            {"step": 1, "role": "source", "file": "test_vuln.js", "line": 6,
             "snippet": "req.params.id", "message": "User-controlled route parameter enters the request handler"},
            {"step": 2, "role": "intermediate", "file": "test_vuln.js", "line": 8,
             "snippet": '"SELECT * FROM users WHERE id = " + req.params.id',
             "message": "Value is concatenated into a SQL string without parameterization"},
            {"step": 3, "role": "sink", "file": "test_vuln.js", "line": 8,
             "snippet": "db.query(...)", "message": "Tainted string reaches the db.query() SQL sink"},
        ],
    },
    {
        "tool_source": "codeql",
        "file": "test_vuln.js",
        "line": 17,
        "severity": "critical",
        "rule_id": "js/command-line-injection",
        "category": "Command Injection",
        "description": "This command line depends on a user-provided value that reaches "
                       "a shell execution sink without validation.",
        "raw_snippet": "exec('ping -c 1 ' + req.body.ip)",
        "taint_path": [
            {"step": 1, "role": "source", "file": "test_vuln.js", "line": 16,
             "snippet": "req.body.ip", "message": "User-controlled request body field enters the handler"},
            {"step": 2, "role": "intermediate", "file": "test_vuln.js", "line": 17,
             "snippet": "'ping -c 1 ' + req.body.ip",
             "message": "Value is concatenated into a shell command string"},
            {"step": 3, "role": "sink", "file": "test_vuln.js", "line": 17,
             "snippet": "exec(...)", "message": "Tainted string reaches the child_process.exec() sink"},
        ],
    },
]


def _sarif_location(location: dict, root: str) -> tuple[str, int, str]:
    """Pull (file, line, region-hint) out of a SARIF location object."""
    physical = (location or {}).get("physicalLocation", {}) or {}
    artifact = physical.get("artifactLocation", {}) or {}
    region = physical.get("region", {}) or {}
    uri = artifact.get("uri", "") or ""
    snippet = ((region.get("snippet") or {}).get("text") or "").strip()
    return _rel_path(uri, root) if os.path.isabs(uri) else (uri or "unknown"), region.get("startLine", 0), snippet


def _extract_taint_path(result: dict, root: str) -> list[dict] | None:
    """Flatten a SARIF codeFlow into an ordered source → sink taint path.

    This is the piece that makes CodeQL findings qualitatively stronger than the
    other four tools: it is evidence that tainted data actually *reaches* a
    dangerous sink, not merely that a suspicious pattern exists somewhere.
    """
    code_flows = result.get("codeFlows") or []
    if not code_flows:
        return None

    thread_flows = (code_flows[0] or {}).get("threadFlows") or []
    if not thread_flows:
        return None

    locations = (thread_flows[0] or {}).get("locations") or []
    if not locations:
        return None

    steps: list[dict] = []
    total = len(locations)
    for index, entry in enumerate(locations):
        location = (entry or {}).get("location", {}) or {}
        file, line, snippet = _sarif_location(location, root)
        message = ((location.get("message") or {}).get("text") or "").strip()
        role = "source" if index == 0 else "sink" if index == total - 1 else "intermediate"
        steps.append({
            "step": index + 1,
            "role": role,
            "file": file,
            "line": line,
            "snippet": _clip(snippet or message, 200),
            "message": _clip(message, 240),
        })
    return steps


def parse_codeql_sarif(payload: dict, root: str) -> list[dict]:
    findings = []
    for run in payload.get("runs", []) or []:
        rules = ((run.get("tool", {}) or {}).get("driver", {}) or {}).get("rules", []) or []
        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId") or "codeql.unknown"

            # Resolve the rule definition for tags (CWEs) and security severity.
            rule: dict = {}
            index = result.get("ruleIndex", (result.get("rule", {}) or {}).get("index"))
            if isinstance(index, int) and 0 <= index < len(rules):
                rule = rules[index] or {}
            elif rule_id:
                rule = next((r for r in rules if r.get("id") == rule_id), {}) or {}

            properties = rule.get("properties", {}) or {}
            tags = properties.get("tags", []) or []
            cwes = [t for t in tags if "cwe" in str(t).lower()]

            level = str(result.get("level")
                        or (rule.get("defaultConfiguration", {}) or {}).get("level", "warning")).lower()
            severity = SARIF_LEVEL.get(level, "medium")
            # A CodeQL security-severity score is a better signal than the SARIF level.
            band = _cvss_band(properties.get("security-severity", ""))
            if band:
                severity = band

            message = (result.get("message", {}) or {}).get("text", "") or \
                      (rule.get("shortDescription", {}) or {}).get("text", "")

            locations = result.get("locations", []) or []
            file, line, snippet = _sarif_location(locations[0] if locations else {}, root)
            taint_path = _extract_taint_path(result, root)

            # A taint path's sink is more precise than the primary location and
            # reads better in a report, so prefer it when present.
            if taint_path:
                sink = taint_path[-1]
                snippet = snippet or sink.get("snippet", "")

            findings.append({
                "tool_source": "codeql",
                "file": file,
                "line": line,
                "severity": severity,
                "rule_id": rule_id,
                "category": categorize(rule_id, f"{message} {' '.join(str(t) for t in tags)}", cwes),
                "description": _clip(message, 800),
                "raw_snippet": _clip(snippet),
                "taint_path": taint_path,
                "cwe": [str(c).split("/")[-1].upper().replace("CWE-", "CWE-") for c in cwes][:3],
            })
    return findings


def run_codeql_tool(root: str, language: str = "javascript") -> tuple[list[dict], dict]:
    """CodeQL deep dataflow analysis — a two-step process.

    1. `codeql database create <db> --language=<lang> --source-root=<root>`
    2. `codeql database analyze <db> <suite> --format=sarifv2.1.0 --output=<sarif>`

    Both steps are slow (minutes on a real repo), which is why this node is
    budgeted and isolated from the other four scanners.
    """
    started = time.time()
    binary = _which("codeql")
    if not binary:
        return CODEQL_SAMPLE, _status("codeql", False, len(CODEQL_SAMPLE),
                                      "codeql CLI not found on PATH", used_sample=True,
                                      duration=time.time() - started)

    language = (language or "javascript").lower()
    extractor = CODEQL_EXTRACTOR.get(language, language)
    suite = CODEQL_SUITES.get(language, CODEQL_SUITES["javascript"])

    workdir = tempfile.mkdtemp(prefix="codeql-")
    db_path = os.path.join(workdir, "db")
    sarif_path = os.path.join(workdir, "results.sarif")
    try:
        # ── Step 1: build the database ──
        code, out, err = _run([
            binary, "database", "create", db_path,
            f"--language={extractor}",
            f"--source-root={root}",
            "--overwrite",
        ], CODEQL_DB_TIMEOUT)

        if code != 0:
            detail = _clip(err or out, 300) or f"database create exited {code}"
            return CODEQL_SAMPLE, _status("codeql", False, len(CODEQL_SAMPLE),
                                          f"database create failed: {detail}",
                                          used_sample=True, duration=time.time() - started)

        # ── Step 2: run the security query suite ──
        code, out, err = _run([
            binary, "database", "analyze", db_path, suite,
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            "--download",
        ], CODEQL_ANALYZE_TIMEOUT)

        if code != 0 and not os.path.isfile(sarif_path):
            detail = _clip(err or out, 300) or f"database analyze exited {code}"
            return CODEQL_SAMPLE, _status("codeql", False, len(CODEQL_SAMPLE),
                                          f"database analyze failed: {detail}",
                                          used_sample=True, duration=time.time() - started)

        with open(sarif_path, "r", encoding="utf-8", errors="replace") as handle:
            findings = parse_codeql_sarif(json.load(handle), root)

        elapsed = time.time() - started
        with_paths = sum(1 for f in findings if f.get("taint_path"))
        if not findings:
            return [], _status("codeql", True, 0,
                               f"{extractor} database built and analyzed — no alerts",
                               duration=elapsed)
        return findings, _status("codeql", True, len(findings),
                                 f"{with_paths} finding(s) carry a full taint path", duration=elapsed)
    except Exception as exc:
        return CODEQL_SAMPLE, _status("codeql", False, len(CODEQL_SAMPLE),
                                      f"unexpected failure: {exc}", used_sample=True,
                                      duration=time.time() - started)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ── Language detection (picks the CodeQL extractor for a repo) ───────────────

LANGUAGE_MARKERS: list[tuple[str, str]] = [
    ("package.json", "javascript"),
    ("tsconfig.json", "typescript"),
    ("pyproject.toml", "python"),
    ("requirements.txt", "python"),
    ("go.mod", "go"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("Gemfile", "ruby"),
    ("Cargo.toml", "rust"),
]

EXTENSION_LANGUAGES: dict[str, str] = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".py": "python", ".go": "go", ".java": "java", ".rb": "ruby", ".cs": "csharp",
}

SKIP_DIRS = set(EXCLUDE_DIRS)


def detect_language(root: str) -> str:
    """Guess the dominant language of a repo, for CodeQL database creation."""
    for marker, language in LANGUAGE_MARKERS:
        if os.path.isfile(os.path.join(root, marker)):
            if language in CODEQL_SUITES:
                return language

    counts: dict[str, int] = {}
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for filename in filenames:
            language = EXTENSION_LANGUAGES.get(os.path.splitext(filename)[1])
            if language:
                counts[language] = counts.get(language, 0) + 1
                scanned += 1
        if scanned > 2000:
            break

    return max(counts, key=counts.get) if counts else "javascript"


# ── Safe-pattern detection (positive evidence) ───────────────────────────────
# The five scanners only report what is wrong. These rules find security
# controls the codebase already gets right, so a report can show what is
# defended rather than only what is broken.

SAFE_PATTERNS: list[tuple[str, str, str, str]] = [
    # (id, regex, control type, description)
    ("safe.sql.parameterized-query",
     r"(?:query|execute|prepare)\s*\(\s*[`'\"][^`'\"]*[?$]\d?[^`'\"]*[`'\"]\s*,\s*[\[(]",
     "database_security",
     "Parameterized query: values are bound as parameters instead of concatenated into SQL, "
     "which neutralizes SQL injection."),
    ("safe.sql.sqlalchemy-text-bindparams",
     r"text\(\s*[`'\"][^`'\"]*:\w+[^`'\"]*[`'\"]\s*\)",
     "database_security",
     "SQLAlchemy `text()` with named bind parameters — the driver escapes the values, "
     "so user input cannot alter the query structure."),
    ("safe.sql.orm-filter",
     r"\.(?:filter_by|filter)\(\s*\w+\s*==?\s*",
     "database_security",
     "ORM query builder used instead of raw SQL, so the ORM handles escaping."),
    ("safe.command.execfile-argv",
     r"(?:execFile|spawn)\s*\(\s*[`'\"][\w.\-/]+[`'\"]\s*,\s*\[",
     "command_execution",
     "Command executed with an argument array rather than a shell string, so shell "
     "metacharacters in user input cannot inject extra commands."),
    ("safe.command.subprocess-list",
     r"subprocess\.(?:run|Popen|check_output|check_call)\s*\(\s*\[",
     "command_execution",
     "`subprocess` invoked with an argument list (no `shell=True`), preventing command injection."),
    ("safe.crypto.bcrypt",
     r"bcrypt\.(?:hash|hashpw|checkpw|compare)|argon2|scrypt|PasswordHasher\(",
     "credential_storage",
     "Passwords handled with a slow, salted hash (bcrypt/argon2/scrypt) rather than a "
     "fast digest, which resists offline cracking."),
    ("safe.xss.dompurify",
     r"DOMPurify\.sanitize|bleach\.clean|escape-html|escapeHtml\(",
     "output_encoding",
     "Untrusted markup is sanitized/escaped before rendering, blocking cross-site scripting."),
    ("safe.xss.textcontent",
     r"\.textContent\s*=",
     "output_encoding",
     "`textContent` used instead of `innerHTML`, so injected markup is rendered as inert text."),
    ("safe.headers.helmet",
     r"helmet\(\)|app\.use\(\s*helmet|SecurityMiddleware|secure_headers",
     "security_headers",
     "Security-header middleware is installed, setting CSP, HSTS and frame protections by default."),
    ("safe.secrets.env-var",
     r"(?:process\.env\.[A-Z_]{4,}|os\.environ(?:\.get)?\[?['\"][A-Z_]{4,})",
     "secret_management",
     "Credentials are read from the environment rather than hardcoded in source."),
    ("safe.auth.jwt-verify",
     r"jwt\.verify\s*\(|jwt\.decode\s*\([^)]*(?:verify=True|algorithms\s*=)",
     "authentication",
     "JWTs are verified with an explicit algorithm allowlist, preventing signature-stripping "
     "and algorithm-confusion attacks."),
    ("safe.validation.schema",
     r"(?:z\.object\(|yup\.object\(|joi\.object\(|BaseModel\)|pydantic)",
     "input_validation",
     "Requests are validated against a declared schema, so malformed input is rejected "
     "before it reaches business logic."),
    ("safe.csrf.protection",
     r"csrf(?:Protection|_protect|Token)|CSRFProtect\(",
     "csrf_protection",
     "CSRF protection middleware is enabled for state-changing requests."),
    ("safe.path.basename-guard",
     r"(?:path\.basename|os\.path\.basename)\s*\(",
     "path_handling",
     "User-supplied filenames are reduced to their basename, stripping `../` traversal sequences."),
]

SAFE_SCAN_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go",
                        ".java", ".rb", ".cs", ".php"}
MAX_SAFE_FILES = 400
MAX_SAFE_FILE_BYTES = 400_000
MAX_SAFE_RESULTS = 12


def detect_safe_patterns(root: str) -> list[dict]:
    """Scan source files for security controls that are already implemented.

    Deliberately cheap: one compiled-regex pass over a bounded number of source
    files, at most one hit reported per control type so the report highlights
    each defense once instead of listing every call site.
    """
    if not os.path.isdir(root):
        return []

    compiled = [(pid, re.compile(pattern), ctype, desc) for pid, pattern, ctype, desc in SAFE_PATTERNS]
    seen_types: set[str] = set()
    results: list[dict] = []
    files_scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for filename in filenames:
            if os.path.splitext(filename)[1] not in SAFE_SCAN_EXTENSIONS:
                continue
            full = os.path.join(dirpath, filename)
            try:
                if os.path.getsize(full) > MAX_SAFE_FILE_BYTES:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.readlines()
            except OSError:
                continue

            files_scanned += 1
            for line_no, line in enumerate(lines, start=1):
                if len(line) > 400:
                    continue
                for pid, regex, ctype, desc in compiled:
                    if ctype in seen_types:
                        continue
                    if regex.search(line):
                        seen_types.add(ctype)
                        results.append({
                            "id": pid,
                            "path": _rel_path(full, root),
                            "line": line_no,
                            "snippet": _clip(line.strip(), 300),
                            "description": desc,
                            "type": ctype,
                        })
                        break
            if len(results) >= MAX_SAFE_RESULTS or files_scanned >= MAX_SAFE_FILES:
                return results
    return results
