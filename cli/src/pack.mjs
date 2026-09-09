/**
 * Package a local directory as a gzipped tarball for upload to a remote backend.
 *
 * The tree is walked in Node — skipping the same directories/files the scanners
 * ignore, and never following symlinks — and the resulting relative file list is
 * handed to the system `tar` via `-T`. Walking ourselves (rather than leaning on
 * tar's `--exclude` globbing, which differs between GNU tar and bsdtar) keeps the
 * archive contents identical on Windows, macOS and Linux, and guarantees only
 * regular files under the root make it in.
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// CLI-side cap on the packaged archive; the backend enforces its own uncompressed
// limits on extraction. A repo bigger than this should be scanned as a Git URL.
export const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // 100 MB

// Mirrors EXCLUDE_DIRS / EXCLUDE_GLOBS in
// backend/app/agents/static_analysis/tools.py.
const EXCLUDE_DIRS = new Set([
  "node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build",
  ".next", "out", "coverage", "vendor", "site-packages", "target",
  ".mypy_cache", ".pytest_cache", ".ruff_cache", ".turbo", ".cache",
]);
const EXCLUDE_SUFFIXES = [".min.js", ".min.css", ".map", ".lock", ".bundle.js"];

const isExcludedFile = (name) => EXCLUDE_SUFFIXES.some((s) => name.endsWith(s));

export function hasTar() {
  try {
    const r = spawnSync("tar", ["--version"], { stdio: "ignore" });
    return !r.error && r.status === 0;
  } catch {
    return false;
  }
}

function walk(root) {
  const files = [];
  const stack = [""]; // relative paths, "" = root
  while (stack.length) {
    const rel = stack.pop();
    const abs = rel ? path.join(root, rel) : root;
    let entries;
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      continue; // unreadable directory — skip it
    }
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue; // never archive links
      const childRel = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) {
        if (!EXCLUDE_DIRS.has(ent.name)) stack.push(childRel);
      } else if (ent.isFile() && !isExcludedFile(ent.name)) {
        files.push(childRel); // forward-slashed; tar accepts these on Windows too
      }
    }
  }
  return files;
}

function safeUnlink(p) {
  try {
    fs.unlinkSync(p);
  } catch {
    /* already gone */
  }
}

/**
 * Build the tarball. Returns { path, fileCount, cleanup }. `cleanup()` removes
 * the archive and must be called by the caller once the upload finishes.
 */
export function packDir(dir) {
  if (!hasTar()) {
    throw new Error(
      "`tar` was not found on your PATH, so local code can't be packaged for a remote backend.\n" +
      "  Fixes: install tar (bundled with Windows 10 1803+, macOS and Linux),\n" +
      "         scan a public Git repo URL instead (the backend clones it),\n" +
      "         or run the backend on this machine and drop --upload."
    );
  }

  const files = walk(dir);
  if (files.length === 0) {
    throw new Error(`Nothing to scan under ${dir} (it's empty, or every file is excluded).`);
  }

  const stamp = `${process.pid}-${Date.now()}`;
  const listPath = path.join(os.tmpdir(), `secura-files-${stamp}.txt`);
  const archivePath = path.join(os.tmpdir(), `secura-upload-${stamp}.tar.gz`);

  try {
    fs.writeFileSync(listPath, files.join("\n") + "\n", "utf8");
    // -C dir + relative names → the paths archive at the tarball root.
    const r = spawnSync("tar", ["-czf", archivePath, "-C", dir, "-T", listPath], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    if (r.error) throw r.error;
    if (r.status !== 0) {
      const stderr = r.stderr ? r.stderr.toString().trim() : "";
      throw new Error(`tar exited ${r.status}${stderr ? `: ${stderr}` : ""}`);
    }
    return {
      path: archivePath,
      fileCount: files.length,
      cleanup: () => safeUnlink(archivePath),
    };
  } catch (err) {
    safeUnlink(archivePath);
    throw new Error(`Failed to package ${dir}: ${err.message}`);
  } finally {
    safeUnlink(listPath); // the list is consumed by tar; drop it either way
  }
}
