# @authtrack/secura

**AuthTrack static analysis (SAST) from the command line.**

`secura` points five independent engines — [Semgrep], [Bearer], [OSV-Scanner],
[Gitleaks] and [CodeQL] — at a repository, merges and deduplicates their
findings, retrieves similar known-vulnerable patterns, then has an LLM confirm
or rule out each finding and write a patch for the confirmed ones. It streams
the whole run live in your terminal and prints a report at the end.

The scanning runs on the **AuthTrack backend**; this CLI is a thin, zero-dependency
client that talks to it. You don't need Python, and you don't need the scanners
installed locally.

[Semgrep]: https://semgrep.dev
[Bearer]: https://www.bearer.com
[OSV-Scanner]: https://google.github.io/osv-scanner/
[Gitleaks]: https://github.com/gitleaks/gitleaks
[CodeQL]: https://codeql.github.com

---

## Install

```bash
npm install -g @authtrack/secura
```

Or run it once, without installing:

```bash
npx @authtrack/secura scan .
```

Requires **Node ≥ 18**. No build step, no native modules.

## Quick start

```bash
# Scan the current directory
secura scan .

# Scan a public GitHub repo (the backend clones it)
secura scan owner/repo
secura scan https://github.com/owner/repo

# Fast pass — skip CodeQL (its database build dominates the run)
secura scan . --fast

# CI gate: exit non-zero if anything HIGH or worse is confirmed
secura scan . --fail-on high

# Save the full machine-readable report
secura scan . --json report.json
```

## Targets

| Target | What happens |
| --- | --- |
| `.` or `./path/to/repo` | A local folder. Sent to the backend to scan (see [Backend](#backend)). |
| `owner/repo` | Public GitHub shorthand. The backend shallow-clones it, scans, then deletes it. |
| `https://github.com/owner/repo`, `git@…`, `ssh://…` | Any public Git URL. Cloned by the backend. |

For a local path, how the code reaches the backend depends on where the backend runs:

- **Local backend** (the default, `http://localhost:8000`): the absolute path is
  sent as-is and scanned in place — nothing is copied.
- **Remote backend** (a `--api` that isn't localhost), or **`--upload`**: the
  directory is packaged into a `tar.gz` (excluding `node_modules`, `.git`, build
  output, lockfiles, minified assets, …) and uploaded. Requires `tar` on your
  PATH (bundled with Windows 10 1803+, macOS and Linux). If `tar` is missing,
  scan a Git URL instead.

## Options

```
-f, --fast                 Skip CodeQL (its DB build dominates the run).
-l, --language <lang>      CodeQL language (javascript, python, java, go, ruby,
                           csharp, cpp). Auto-detected when omitted.
-t, --max-triage <n>       Cap findings sent to LLM triage (default 25).
    --fail-on <sev>        Exit 1 if a confirmed finding is >= this severity
                           (critical|high|medium|low). For CI gates.
-o, --json <path>          Write the full report as JSON to <path>.
    --max-findings <n>     How many confirmed findings to print (default 20).
    --show-fixes           Print the generated fix diffs in full.
-q, --quiet                Suppress the live view; print only the report.
    --api <url>            Backend base URL (default $SECURA_API or
                           http://localhost:8000/api/v1).
    --token <token>        Bearer token, if the backend requires one
                           (default $SECURA_TOKEN).
    --upload               Package and upload the local dir even for a local
                           backend (automatic for a remote --api).
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed; no `--fail-on` breach. |
| `1` | `--fail-on` gate breached (a confirmed finding at or above the threshold). |
| `2` | Bad target, or the scan failed. |
| `130` | Interrupted (Ctrl-C). |

## Backend

`secura` needs a reachable AuthTrack backend. Point it at one with `--api` or the
`SECURA_API` environment variable (matching the web app's `NEXT_PUBLIC_API_URL`):

```bash
export SECURA_API="https://scans.example.com/api/v1"
secura scan owner/repo
```

The default is `http://localhost:8000/api/v1`. The scan endpoints are unauthenticated;
`--token` / `SECURA_TOKEN` is sent as a bearer header only if provided, so it keeps
working if auth is added later.

## CI example

```yaml
# GitHub Actions — fail the build on a confirmed high+ finding
- name: SAST
  run: npx @authtrack/secura scan . --fast --fail-on high --json sast.json
  env:
    SECURA_API: ${{ secrets.SECURA_API }}
```

---

## Publishing (maintainers)

This package publishes from the `cli/` directory of the AuthTrack repo. It is
plain ESM with no build step, so publishing is just:

```bash
cd cli
npm login                     # once per machine
npm version patch             # 0.1.0 -> 0.1.1 (bumps package.json + git tag)
npm publish --access public   # scoped packages need --access public on first publish
```

Notes:

- **Scope.** The name `@authtrack/secura` requires the `@authtrack` org to exist
  on npm and your account to be a member. Create it at
  <https://www.npmjs.com/org/create>, or rename the package to an unscoped name
  you own (e.g. `authtrack-secura`) in `package.json` — the `bin` stays `secura`
  either way, so `secura scan …` is unchanged for users.
- **What ships.** Only `bin/`, `src/` and `README.md` (the `files` allowlist).
  Verify with `npm pack --dry-run` before publishing.
- **Smoke test the tarball.** `npm pack` then
  `npm i -g ./authtrack-secura-<version>.tgz` and run `secura --help`.

## License

MIT
