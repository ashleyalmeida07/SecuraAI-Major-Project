/**
 * Backend client — POSTs to the static-analysis stream endpoints and yields the
 * parsed SSE events.
 *
 * The wire format matches backend/app/api/scan.py: newline-delimited frames of
 * `data: {json}\n\n`, each carrying one of:
 *   { event: "start",       message }
 *   { event: "node_update", node, state }
 *   { event: "complete",    message }
 *   { event: "error",       message }
 *
 * This mirrors the reader loop in frontend/src/lib/api.ts (split on "\n\n",
 * parse `data:` lines) so the CLI and the browser consume an identical stream.
 * Uses Node's global fetch + Web Streams (Node >= 18) — no dependencies.
 */

function authHeaders(token, extra = {}) {
  const h = { ...extra };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

async function openStream(url, token, headers, body) {
  let res;
  try {
    res = await fetch(url, { method: "POST", headers: authHeaders(token, headers), body });
  } catch (err) {
    throw new Error(
      `Could not reach the backend at ${url}\n` +
      `  ${err.message}\n` +
      `  Is it running? Point elsewhere with --api <url> or the SECURA_API env var.`
    );
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.text()).slice(0, 500).trim();
    } catch {
      /* ignore */
    }
    throw new Error(`Backend returned ${res.status} ${res.statusText}${detail ? `\n  ${detail}` : ""}`);
  }
  if (!res.body) throw new Error("Backend sent an empty response body.");
  return res;
}

async function* readSse(res) {
  const decoder = new TextDecoder();
  const reader = res.body.getReader();
  let buffer = "";

  const emit = function* (frame) {
    // A frame may hold several lines; the backend uses a single `data:` line.
    for (const rawLine of frame.split("\n")) {
      if (!rawLine.startsWith("data:")) continue;
      const jsonStr = rawLine.slice(rawLine.indexOf(":") + 1).trim();
      if (!jsonStr) continue;
      try {
        yield JSON.parse(jsonStr);
      } catch {
        // Malformed frame — skip it (the browser client does the same).
      }
    }
  };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() || ""; // keep the trailing partial frame
    for (const frame of frames) yield* emit(frame);
  }
  // Flush any final frame that arrived without a trailing blank line.
  const tail = buffer.trim();
  if (tail) yield* emit(tail);
}

/** Stream a scan of a repo URL or a co-located local path (JSON body). */
export async function* streamStatic(api, token, body) {
  const res = await openStream(
    `${api}/scan/stream/static`,
    token,
    { "Content-Type": "application/json" },
    JSON.stringify(body)
  );
  yield* readSse(res);
}

/** Stream a scan of uploaded local code (multipart tar.gz + form fields). */
export async function* streamStaticUpload(api, token, form) {
  // Let fetch set the multipart Content-Type (with boundary) from the FormData.
  const res = await openStream(`${api}/scan/stream/static/upload`, token, {}, form);
  yield* readSse(res);
}
