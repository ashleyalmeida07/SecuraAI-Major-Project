#!/usr/bin/env node
/**
 * secura — AuthTrack static analysis CLI (npm distribution).
 *
 * A dependency-free Node client for the backend's static-analysis SSE endpoints.
 * The heavy scanning runs on the backend; this renders the streamed run and the
 * final report in your terminal. See ../README.md.
 */

import { parseArgs } from "../src/args.mjs";
import { runScan } from "../src/commands/scan.mjs";
import { printHelp, printScanHelp } from "../src/help.mjs";
import { red, showCursor } from "../src/ansi.mjs";

const VERSION = "0.1.0";

// Canonical long name → { type, alias }. Mirrors the Python `scan` command's
// flags, plus the API-client-only --api / --token / --upload.
const SCAN_SPEC = {
  fast: { type: "boolean", alias: "f" },
  language: { type: "string", alias: "l" },
  "max-triage": { type: "number", alias: "t" },
  "fail-on": { type: "string" },
  json: { type: "string", alias: "o" },
  "max-findings": { type: "number" },
  "show-fixes": { type: "boolean" },
  quiet: { type: "boolean", alias: "q" },
  api: { type: "string" },
  token: { type: "string" },
  upload: { type: "boolean" },
  help: { type: "boolean", alias: "h" },
};

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    return 0;
  }
  if (cmd === "version" || cmd === "--version" || cmd === "-v") {
    process.stdout.write(`secura ${VERSION} — AuthTrack static analysis CLI (npm)\n`);
    return 0;
  }
  if (cmd === "scan") {
    const { values, positionals, errors } = parseArgs(argv.slice(1), SCAN_SPEC);
    if (values.help) {
      printScanHelp();
      return 0;
    }
    if (errors.length) {
      for (const e of errors) process.stderr.write(`${red("error:")} ${e}\n`);
      process.stderr.write("Run `secura scan --help` for usage.\n");
      return 2;
    }
    return runScan(values, positionals);
  }

  process.stderr.write(`${red(`Unknown command '${cmd}'.`)} Try \`secura --help\`.\n`);
  return 2;
}

main()
  .then((code) => process.exit(code ?? 0))
  .catch((err) => {
    showCursor(); // never leave the terminal cursor hidden after a crash
    process.stderr.write(`${red("Fatal:")} ${err && err.stack ? err.stack : String(err)}\n`);
    process.exit(2);
  });
