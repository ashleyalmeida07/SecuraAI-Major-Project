/**
 * Zero-dependency ANSI styling.
 *
 * Colour is enabled only when stdout is a TTY and `NO_COLOR` is unset (honouring
 * https://no-color.org), or forced on with `FORCE_COLOR`. When disabled every
 * helper is the identity function, so the same render code produces clean text
 * for pipes, CI logs and `--json` redirects.
 */

const enabled =
  !process.env.NO_COLOR &&
  (Boolean(process.env.FORCE_COLOR) || Boolean(process.stdout.isTTY));

function wrap(open, close) {
  const prefix = `\x1b[${open}m`;
  const suffix = `\x1b[${close}m`;
  return (s) => (enabled ? prefix + String(s) + suffix : String(s));
}

export const colorEnabled = enabled;

export const bold = wrap(1, 22);
export const dim = wrap(2, 22);

export const red = wrap(31, 39);
export const green = wrap(32, 39);
export const yellow = wrap(33, 39);
export const blue = wrap(34, 39);
export const magenta = wrap(35, 39);
export const cyan = wrap(36, 39);
export const gray = wrap(90, 39); // bright_black
export const brightRed = wrap(91, 39);
export const white = wrap(37, 39);

// Mirrors SEVERITY_COLOR in backend/app/cli/main.py.
const SEVERITY_FN = {
  critical: brightRed,
  high: red,
  medium: yellow,
  low: cyan,
  info: gray,
};

/** Uppercase, severity-coloured label — e.g. a red "HIGH". */
export function severityText(name) {
  const key = String(name || "info").toLowerCase();
  const fn = SEVERITY_FN[key] || white;
  return fn(key.toUpperCase());
}

// ── Cursor control (live view) ──

export const hideCursor = () => {
  if (enabled) process.stdout.write("\x1b[?25l");
};
export const showCursor = () => {
  if (enabled) process.stdout.write("\x1b[?25h");
};

const ANSI_RE = /\x1b\[[0-9;]*m/g;

/** Visible length of a string, ignoring ANSI escape sequences. */
export function visibleLength(s) {
  return s.replace(ANSI_RE, "").length;
}

/**
 * Truncate to `width` visible columns, preserving ANSI codes and appending an
 * ellipsis when clipped. Keeps the live view from wrapping in a narrow terminal
 * (which would break the cursor-up redraw).
 */
export function clip(s, width) {
  if (width <= 0 || visibleLength(s) <= width) return s;
  let out = "";
  let vis = 0;
  for (let i = 0; i < s.length; ) {
    const rest = s.slice(i);
    const m = rest.match(/^\x1b\[[0-9;]*m/);
    if (m) {
      out += m[0];
      i += m[0].length;
      continue;
    }
    if (vis >= width - 1) {
      out += "…";
      break;
    }
    out += s[i];
    vis += 1;
    i += 1;
  }
  return out + (enabled ? "\x1b[0m" : "");
}
