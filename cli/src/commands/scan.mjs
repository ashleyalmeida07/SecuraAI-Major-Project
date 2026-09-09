/**
 * `secura scan` — drive a static-analysis run against the backend and render it.
 *
 * Transport is chosen by target:
 *   • repo URL / owner/repo  → sent verbatim as target_path; the backend clones it.
 *   • local path + local backend (default) → the absolute path is scanned in place.
 *   • local path + remote backend, or --upload → the dir is tar.gz'd and uploaded.
 *
 * Exit codes match the Python CLI: 0 clean · 1 --fail-on gate breached ·
 * 2 bad target / scan failure · 130 interrupted.
 */

import fs from "node:fs";
import path from "node:path";

import { resolveConfig, isLocalBackend } from "../config.mjs";
import { classifyTarget } from "../target.mjs";
import { streamStatic, streamStaticUpload } from "../client.mjs";
import { packDir, MAX_UPLOAD_BYTES } from "../pack.mjs";
import { ScanMonitor, SEVERITY_RANK } from "../monitor.mjs";
import { LiveView, renderLive, printReport } from "../render.mjs";
import { bold, dim, red, green, yellow, cyan } from "../ansi.mjs";

const errline = (s) => process.stderr.write(s + "\n");
const outline = (s = "") => process.stdout.write(s + "\n");

export async function runScan(values, positionals) {
  const rawTarget = String(positionals[0] ?? ".").trim() || ".";
  const includeCodeql = !values.fast;
  const language = values.language || "";
  const maxTriage = values["max-triage"] ?? 25;
  const maxFindings = values["max-findings"] ?? 20;
  const failOn = String(values["fail-on"] || "").toLowerCase();
  const jsonOut = values.json || "";
  const showFixes = Boolean(values["show-fixes"]);
  const quiet = Boolean(values.quiet);
  const forceUpload = Boolean(values.upload);

  const { api, token } = resolveConfig(values);
  const target = classifyTarget(rawTarget);

  // Validate a local path up front (mirrors the Python CLI's exit-2 checks).
  if (target.kind === "path") {
    if (!fs.existsSync(target.value)) {
      errline(`${red("Not found:")} '${rawTarget}' is neither an existing path nor a Git repo URL.`);
      return 2;
    }
    if (!fs.statSync(target.value).isDirectory()) {
      errline(`${red("Not a directory:")} ${rawTarget}`);
      return 2;
    }
  }

  const remote = !isLocalBackend(api);
  const transport = target.kind === "url" ? "url" : forceUpload || remote ? "upload" : "path";

  if (!quiet) {
    outline();
    outline(`${bold("secura")} scanning ${cyan(target.display)}`);
    outline(dim(`backend  ${api}`));
    if (target.kind === "url") outline(dim("remote repo — the backend shallow-clones it, scans, then removes it"));
    else if (transport === "upload") outline(dim("packaging local code and uploading it to the backend"));
    else outline(dim("scanning the path in place on the backend host"));
    if (values.fast) outline(dim("--fast: CodeQL skipped, no taint paths in this run"));
    outline();
  }

  const monitor = new ScanMonitor(target.display, includeCodeql);
  let cleanup = () => {};

  try {
    let events;
    if (transport === "upload") {
      const packed = packDir(target.value);
      cleanup = packed.cleanup;
      const { size } = fs.statSync(packed.path);
      if (size > MAX_UPLOAD_BYTES) {
        cleanup();
        errline(
          `${red("Too large:")} packaged code is ${(size / 1e6).toFixed(0)} MB ` +
          `(limit ${(MAX_UPLOAD_BYTES / 1e6).toFixed(0)} MB). ` +
          `Scan a Git URL, or run the backend locally and drop --upload.`
        );
        return 2;
      }
      if (!quiet) outline(dim(`packaged ${packed.fileCount} file(s) → ${(size / 1e6).toFixed(1)} MB`));

      const buf = fs.readFileSync(packed.path);
      const form = new FormData();
      form.append("include_codeql", String(includeCodeql));
      form.append("codeql_language", language);
      form.append("max_triage", String(maxTriage));
      form.append("file", new Blob([buf], { type: "application/gzip" }), "code.tar.gz");
      events = streamStaticUpload(api, token, form);
    } else {
      events = streamStatic(api, token, {
        target_path: target.value,
        include_codeql: includeCodeql,
        codeql_language: language,
        max_triage: maxTriage,
      });
    }

    const streamCode = await consume(events, monitor, quiet);
    if (streamCode !== 0) return streamCode;
  } catch (err) {
    errline(`\n${red("Scan failed:")} ${err && err.message ? err.message : String(err)}`);
    return 2;
  } finally {
    cleanup();
  }

  printReport(monitor.report, { showFixes, maxFindings });

  if (jsonOut) {
    try {
      const dest = path.resolve(jsonOut);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, JSON.stringify(monitor.report, null, 2), "utf8");
      outline(`\n${green("Report written to")} ${cyan(jsonOut)}`);
    } catch (err) {
      outline(`\n${yellow(`Could not write ${jsonOut}: ${err.message}`)}`);
    }
  }

  // ── CI gate ──
  if (failOn) {
    const threshold = SEVERITY_RANK[failOn];
    if (threshold === undefined) {
      outline(yellow(`Unknown --fail-on severity '${failOn}' — ignored.`));
    } else {
      const breaching = (monitor.report.confirmed_findings || []).filter(
        (f) => (SEVERITY_RANK[String(f.final_severity || f.severity || "info").toLowerCase()] ?? 0) >= threshold
      );
      if (breaching.length) {
        outline(`\n${red(`${breaching.length} confirmed finding(s) at or above ${failOn.toUpperCase()}.`)}`);
        return 1;
      }
      outline(`\n${green(`No confirmed findings at or above ${failOn.toUpperCase()}.`)}`);
    }
  }

  return 0;
}

/**
 * Consume the event stream, driving the live view. Returns 0 on a clean run, or
 * 2 if the backend emitted an error event. A spinner timer advances the live
 * frame even while the backend is quiet (e.g. CodeQL building its database).
 */
async function consume(events, monitor, quiet) {
  const live = new LiveView();
  const useLive = !quiet && live.active;
  let frame = 0;
  let timer = null;

  if (useLive) {
    live.start();
    timer = setInterval(() => {
      frame += 1;
      live.render(renderLive(monitor, frame));
    }, 120);
  }

  const onSigint = () => {
    if (timer) clearInterval(timer);
    live.stop();
    errline(`\n${yellow("Interrupted.")}`);
    process.exit(130);
  };
  process.once("SIGINT", onSigint);

  try {
    for await (const evt of events) {
      if (!evt || typeof evt !== "object") continue;
      switch (evt.event) {
        case "node_update":
          monitor.ingest(evt.node, evt.state);
          if (useLive) live.render(renderLive(monitor, frame));
          break;
        case "complete":
          monitor.stage = "done";
          if (useLive) live.render(renderLive(monitor, frame));
          break;
        case "error":
          if (timer) clearInterval(timer);
          if (useLive) {
            live.render(renderLive(monitor, frame));
            live.stop();
          }
          errline(`\n${red("Backend error:")} ${evt.message || "unknown error"}`);
          return 2;
        default:
          break; // "start" and any future events — ignore
      }
    }
    return 0;
  } finally {
    if (timer) clearInterval(timer);
    live.stop();
    process.removeListener("SIGINT", onSigint);
  }
}
