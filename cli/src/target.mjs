/**
 * Classify a scan target as a Git repo or a local path.
 *
 * Mirrors is_git_url / normalize_git_url in
 * backend/app/agents/static_analysis/tools.py (and the isGitUrl already ported
 * into frontend/src/components/scan/cli-hint.tsx) so the CLI, the web UI and the
 * backend agree on what counts as a repo URL.
 *
 * A URL target is sent to the backend verbatim as `target_path`; the graph's
 * dispatch node shallow-clones and normalises it (including `owner/repo`
 * shorthand), exactly as the Python CLI relies on.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const GIT_URL_RE = /^(?:https?:\/\/|git@|ssh:\/\/|git:\/\/)[\w.@:\/~-]+?(?:\.git)?\/?$/i;
const GIT_SHORTHAND_RE = /^[\w.-]+\/[\w.-]+$/;

export function isGitUrl(target) {
  if (!target) return false;
  const t = String(target).trim();
  if (!t) return false;
  // An existing local path is never a URL, even if it looks like owner/repo.
  try {
    if (fs.existsSync(t)) return false;
  } catch {
    /* ignore fs errors — fall through to the pattern tests */
  }
  if (GIT_URL_RE.test(t)) return true;
  return GIT_SHORTHAND_RE.test(t) && !/^[.\/~]/.test(t);
}

function expandHome(p) {
  if (p === "~") return os.homedir();
  if (p.startsWith("~/") || p.startsWith("~\\")) return path.join(os.homedir(), p.slice(2));
  return p;
}

/**
 * → { kind: "url", value, display } for a repo (value = raw target, sent as-is),
 * → { kind: "path", value, display } for a local dir (value = absolute path).
 */
export function classifyTarget(rawTarget) {
  const raw = String(rawTarget ?? ".").trim() || ".";
  if (isGitUrl(raw)) {
    return { kind: "url", value: raw, display: raw };
  }
  const resolved = path.resolve(expandHome(raw));
  return { kind: "path", value: resolved, display: raw };
}
