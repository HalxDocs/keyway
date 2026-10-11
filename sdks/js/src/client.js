import { KeywayError } from "./errors.js";

/**
 * @typedef {Object} Identity
 * @property {string} email verified login identifier for account matching
 * @property {string} name human-readable display name, possibly empty
 * @property {string[]} groups normalized group memberships, possibly empty
 */

/**
 * @typedef {Object} KeywayClientOptions
 * @property {(input: any, init?: any) => Promise<any>} [fetch] fetch implementation (defaults to global fetch)
 * @property {number} [timeoutMs] request timeout in ms (implemented via AbortSignal.timeout)
 */

/**
 * Client talks to one Keyway deployment.
 * Mirrors Go `pkg/client.Client`: base URL validated once at construction,
 * `buildAuthorizeUrl` builds the redirect, `exchangeCode` redeems the code.
 */
export class KeywayClient {
  /**
   * @param {string} baseUrl e.g. "http://127.0.0.1:8080" (trailing slash trimmed)
   * @param {KeywayClientOptions} [options]
   */
  constructor(baseUrl, options = {}) {
    if (typeof baseUrl !== "string" || baseUrl.trim() === "") {
      throw new KeywayError("invalid_request", "base URL is required");
    }
    const trimmed = baseUrl.trim().replace(/\/+$/, "");
    try {
      // Throws on malformed URLs like "://bad" — mirrors Go url.ParseRequestURI.
      // Also rejects strings with no host (e.g. "https:") the way Go does.
      const parsed = new URL(trimmed);
      if (!parsed.host) {
        throw new KeywayError("invalid_request", "invalid base URL");
      }
    } catch (err) {
      if (err instanceof KeywayError) throw err;
      throw new KeywayError("invalid_request", "invalid base URL");
    }
    this.baseUrl = trimmed;
    this.fetchImpl =
      options.fetch ??
      (typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : undefined);
    if (!this.fetchImpl) {
      throw new KeywayError("invalid_request", "no fetch implementation available");
    }
    this.timeoutMs = options.timeoutMs;
  }

  /**
   * Build the redirect your app sends the user to. `state` is your own CSRF
   * token; Keyway echoes it back as `?state=` alongside `?code=`.
   * Empty `state`/`connection` are omitted (never `state=` leakage).
   *
   * @param {{ tenant: string, redirectUri: string, state?: string, connection?: string }} params
   * @returns {string}
   */
  buildAuthorizeUrl({ tenant, redirectUri, state = "", connection = "" } = {}) {
    if (!tenant || !redirectUri) {
      throw new KeywayError("invalid_request", "tenant and redirectUri are required");
    }
    const url = new URL(`${this.baseUrl}/authorize`);
    url.searchParams.set("tenant", tenant);
    url.searchParams.set("redirect_uri", redirectUri);
    if (state) url.searchParams.set("state", state);
    if (connection) url.searchParams.set("connection", connection);
    return url.toString();
  }

  /**
   * Redeem one single-use code for its verified identity. `redirectUri` must
   * match the one used in `buildAuthorizeUrl` or redemption fails closed.
   *
   * @param {{ code: string, redirectUri: string, signal?: AbortSignal }} params
   * @returns {Promise<Identity>}
   */
  async exchangeCode({ code, redirectUri, signal } = {}) {
    if (!code || !redirectUri) {
      throw new KeywayError("invalid_request", "code and redirectUri are required");
    }
    const body = new URLSearchParams({ code, redirect_uri: redirectUri });
    let res;
    try {
      const init = {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        signal: signal ?? (this.timeoutMs ? AbortSignal.timeout(this.timeoutMs) : undefined),
      };
      res = await this.fetchImpl(`${this.baseUrl}/token`, init);
    } catch (err) {
      if (err instanceof KeywayError) throw err;
      throw new KeywayError("network_error", err?.message ?? "request failed");
    }
    if (!res.ok) {
      let codeOut = "invalid_grant";
      let desc = res.statusText ?? "";
      try {
        const data = await res.json();
        if (data && typeof data === "object") {
          if (typeof data.error === "string" && data.error) codeOut = data.error;
          desc = data.error_description ?? data.error ?? desc;
        }
      } catch {
        // Non-JSON error body: keep status text.
      }
      throw new KeywayError(codeOut, desc || `request failed with status ${res.status}`, res.status);
    }
    let identity;
    try {
      identity = await res.json();
    } catch (err) {
      throw new KeywayError("invalid_grant", "could not decode identity");
    }
    if (!identity || typeof identity.email !== "string" || identity.email === "") {
      throw new KeywayError("invalid_grant", "identity has no email");
    }
    return {
      email: identity.email,
      name: typeof identity.name === "string" ? identity.name : "",
      groups: Array.isArray(identity.groups) ? identity.groups : [],
    };
  }
}
