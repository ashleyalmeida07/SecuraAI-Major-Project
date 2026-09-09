/**
 * A tiny, dependency-free argv parser.
 *
 * Handles the shapes the `secura` commands need and nothing more:
 *   --flag            boolean true
 *   --key value       string / number (next token is the value)
 *   --key=value       string / number (inline)
 *   -f                short boolean (clusterable: -fq)
 *   -l value | -lvalue | -l=value   short with a value
 *   --                everything after is positional
 *
 * `spec` maps a canonical long name → { type: "boolean"|"string"|"number", alias?: "x" }.
 * Returns { values, positionals, errors }. Unknown options and malformed
 * numbers are collected in `errors` rather than thrown, so the caller decides
 * whether to abort or show usage.
 */
export function parseArgs(argv, spec) {
  const aliasToName = {};
  for (const [name, opt] of Object.entries(spec)) {
    if (opt.alias) aliasToName[opt.alias] = name;
  }

  const values = {};
  const positionals = [];
  const errors = [];

  const coerce = (opt, raw, label) => {
    if (opt.type === "number") {
      const n = Number(raw);
      if (Number.isNaN(n)) {
        errors.push(`${label} expects a number, got '${raw}'`);
        return undefined;
      }
      return n;
    }
    return raw;
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === "--") {
      positionals.push(...argv.slice(i + 1));
      break;
    }

    // Long option: --name, --name=value
    if (arg.startsWith("--")) {
      let key = arg.slice(2);
      let inline;
      const eq = key.indexOf("=");
      if (eq !== -1) {
        inline = key.slice(eq + 1);
        key = key.slice(0, eq);
      }
      const name = spec[key] ? key : aliasToName[key];
      if (!name) {
        errors.push(`unknown option --${key}`);
        continue;
      }
      const opt = spec[name];
      if (opt.type === "boolean") {
        values[name] = inline === undefined ? true : /^(1|true|yes|on)$/i.test(inline);
      } else {
        let raw = inline;
        if (raw === undefined) {
          raw = argv[++i];
          if (raw === undefined) {
            errors.push(`--${key} needs a value`);
            continue;
          }
        }
        const v = coerce(opt, raw, `--${key}`);
        if (v !== undefined) values[name] = v;
      }
      continue;
    }

    // Short option(s): -f, -fq, -l value, -lvalue, -l=value
    if (arg.length > 1 && arg[0] === "-") {
      const chars = arg.slice(1);
      for (let c = 0; c < chars.length; c += 1) {
        const ch = chars[c];
        const name = aliasToName[ch];
        if (!name) {
          errors.push(`unknown option -${ch}`);
          break;
        }
        const opt = spec[name];
        if (opt.type === "boolean") {
          values[name] = true;
          continue; // allow clustering, e.g. -fq
        }
        // value option consumes the rest of this token, or the next argv entry
        let raw = chars.slice(c + 1);
        if (raw.startsWith("=")) raw = raw.slice(1);
        if (!raw) {
          raw = argv[++i];
          if (raw === undefined) {
            errors.push(`-${ch} needs a value`);
            break;
          }
        }
        const v = coerce(opt, raw, `-${ch}`);
        if (v !== undefined) values[name] = v;
        break; // rest of the token was the value
      }
      continue;
    }

    positionals.push(arg);
  }

  return { values, positionals, errors };
}
