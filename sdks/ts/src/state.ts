import { KeywayError } from "./errors.js";

/**
 * Mint one random CSRF state token (16 bytes, hex) via WebCrypto.
 * Available on Node 18+ and all modern browsers/runtimes.
 */
export function generateState(): string {
  const crypto = globalThis.crypto;
  if (!crypto?.getRandomValues) {
    throw new KeywayError("internal", "no secure random source available");
  }
  const raw = crypto.getRandomValues(new Uint8Array(16));
  return [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Extract `{code, state}` from an app callback URL.
 * Returns empty strings (not null) for missing params so the caller can
 * fail closed the same way the Go demo does before calling exchange.
 */
export function parseCallbackUrl(url: string | URL): { code: string; state: string } {
  let parsed: URL;
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
