/**
 * Resolve where the CLI talks to and how.
 *
 * The backend's scan router has no auth, so the token is optional; it is sent
 * as a bearer header only when present, so this works unchanged if auth is
 * added later.
 */

// Matches frontend/src/lib/api.ts (API_BASE) so the CLI and the web app default
// to the same backend.
const DEFAULT_API = "http://localhost:8000/api/v1";

export function resolveConfig(values) {
  const raw = values.api || process.env.SECURA_API || DEFAULT_API;
  const api = raw.replace(/\/+$/, ""); // trim trailing slashes
  const token = values.token || process.env.SECURA_TOKEN || "";
  return { api, token };
}

/**
 * True when the API base points at this machine. A local path target can then
 * be scanned in place (sent as `target_path`); otherwise it must be uploaded.
 */
export function isLocalBackend(api) {
  try {
    const { hostname } = new URL(api);
    return ["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"].includes(hostname);
  } catch {
    // An unparseable base is treated as local — the request will fail loudly
    // either way, and this keeps the default (no upload) for odd inputs.
    return true;
  }
}
