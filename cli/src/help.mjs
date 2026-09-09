/** Help / usage text for the `secura` CLI. */

import { bold, dim, cyan } from "./ansi.mjs";

export function printHelp() {
  const p = (s = "") => process.stdout.write(s + "\n");
  p();
  p(`${bold("secura")} — AuthTrack static analysis (SAST) from the command line`);
  p();
  p("Streams a five-scanner scan (Semgrep, Bearer, OSV-Scanner, Gitleaks, CodeQL)");
  p("from the AuthTrack backend and renders it live in your terminal.");
  p();
  p(bold("USAGE"));
  p(`  secura scan [target] [options]`);
  p(`  secura version`);
  p(`  secura --help`);
  p();
  p(bold("TARGETS"));
  p(`  ${cyan(".")}                        the current directory (default)`);
  p(`  ${cyan("./path/to/repo")}           a local folder`);
  p(`  ${cyan("owner/repo")}               a public GitHub repo (shorthand)`);
  p(`  ${cyan("https://github.com/o/r")}   any public Git URL (cloned by the backend)`);
  p();
  p(bold("COMMON"));
  p(`  secura scan .`);
  p(`  secura scan owner/repo --fast`);
  p(`  secura scan . --fail-on high            ${dim("# CI gate")}`);
  p(`  secura scan . --json report.json`);
  p();
  p(`Run ${cyan("secura scan --help")} for every flag.`);
  p();
}

export function printScanHelp() {
  const p = (s = "") => process.stdout.write(s + "\n");
  p();
  p(`${bold("secura scan")} [target] [options]`);
  p();
  p("Fans out to five scanners at once, merges and deduplicates their findings,");
  p("retrieves similar known-vulnerable patterns, then has an LLM confirm or rule");
  p("out each finding and write a patch for the confirmed ones.");
  p();
  p(bold("OPTIONS"));
  p(`  -f, --fast                 Skip CodeQL (its DB build dominates the run).`);
  p(`  -l, --language <lang>      CodeQL language (javascript, python, java, go,`);
  p(`                             ruby, csharp, cpp). Auto-detected when omitted.`);
  p(`  -t, --max-triage <n>       Cap findings sent to LLM triage (default 25).`);
  p(`      --fail-on <sev>        Exit 1 if a confirmed finding is ≥ this severity`);
  p(`                             (critical|high|medium|low). For CI gates.`);
  p(`  -o, --json <path>          Write the full report as JSON to <path>.`);
  p(`      --max-findings <n>     How many confirmed findings to print (default 20).`);
  p(`      --show-fixes           Print the generated fix diffs in full.`);
  p(`  -q, --quiet                Suppress the live view; print only the report.`);
  p();
  p(bold("BACKEND"));
  p(`      --api <url>            Backend base URL`);
  p(`                             (default $SECURA_API or http://localhost:8000/api/v1).`);
  p(`      --token <token>        Bearer token, if the backend requires one`);
  p(`                             (default $SECURA_TOKEN).`);
  p(`      --upload               Package the local dir and upload it, even for a`);
  p(`                             local backend. Automatic for a remote --api.`);
  p();
  p(bold("EXIT CODES"));
  p(`  0  clean      1  --fail-on breached      2  bad target / failure      130  interrupted`);
  p();
}
