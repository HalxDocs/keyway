import { KeywayError } from "./errors.js";

/**
 * Mint one random CSRF state token (16 bytes, hex).
 * Uses WebCrypto; falls back to Node's crypto on old runtimes.
 * @returns {string}
 */
export function generateState() {
  const g = globalThis.crypto;
  if (g?.getRandomValues) {
    const raw = g.getRandomValues(new Uint8Array(16));
    return [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  // Fallback for runtimes without WebCrypto (Node <19 edge cases).
  // Dynamic import avoided to keep this sync; use require-style fallback.
  const nodeCrypto = globalThis.process?.getBuiltinModule?.("crypto");
  if (nodeCrypto?.randomBytes) {
    return nodeCrypto.randomBytes(16).toString("hex");
  }
  throw new KeywayError("internal", "no secure random source available");
}

/**
 * Extract `{code, state}` from an app callback URL.
 * Returns empty strings (not null) for missing params so the caller can
 * fail closed the same way the Go demo does before calling exchange.
 *
 * @param {string | URL} url
 * @returns {{ code: string, state: string }}
 */
export function parseCallbackUrl(url) {
  let parsed;
  try {
    parsed = typeof url === "string" ? new URL(url) : url;
  } catch {
    throw new KeywayError("invalid_request", "unreadable callback URL");
  }
  return {
    code: parsed.searchParams.get("code") ?? "",
    state: parsed.searchParams.get("state") ?? "",
  };
}
