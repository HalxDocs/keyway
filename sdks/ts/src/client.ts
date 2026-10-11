import { KeywayError } from "./errors.js";

/** Normalized user your app receives after SSO. Raw IdP claims never cross this boundary. */
export interface Identity {
  /** Verified login identifier for account matching. */
  email: string;
  /** Human-readable display name, possibly empty. */
  name: string;
  /** Normalized group memberships, possibly empty. */
  groups: string[];
}

export interface KeywayClientOptions {
  /** Fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch;
  /** Request timeout in ms (implemented via AbortSignal.timeout). */
  timeoutMs?: number;
}

export interface AuthorizeUrlParams {
  tenant: string;
  redirectUri: string;
  /** Your own CSRF token; echoed back as ?state=. Omitted when empty. */
  state?: string;
  /** Required only when the tenant has 2+ active connections. Omitted when empty. */
  connection?: string;
}

export interface ExchangeCodeParams {
  code: string;
  redirectUri: string;
  signal?: AbortSignal;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Client talks to one Keyway deployment.
 * Mirrors Go `pkg/client.Client`: base URL validated once at construction,
 * `buildAuthorizeUrl` builds the redirect, `exchangeCode` redeems the code.
 */
export class KeywayClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs?: number;

  /**
   * @param baseUrl e.g. "http://127.0.0.1:8080" (trailing slash trimmed)
   */
  constructor(baseUrl: string, options: KeywayClientOptions = {}) {
    if (typeof baseUrl !== "string" || baseUrl.trim() === "") {
      throw new KeywayError("invalid_request", "base URL is required");
    }
    const trimmed = baseUrl.trim().replace(/\/+$/, "");
    try {
      // Mirrors Go url.ParseRequestURI: absolute URL with a host required.
      const parsed = new URL(trimmed);
      if (!parsed.host) {
        throw new KeywayError("invalid_request", "invalid base URL");
      }
    } catch (err) {
      if (err instanceof KeywayError) throw err;
      throw new KeywayError("invalid_request", "invalid base URL");
    }
    this.baseUrl = trimmed;
    const fetchImpl =
      options.fetch ??
      (typeof globalThis.fetch === "function" ? globalThis.fetch.bind(globalThis) : undefined);
    if (!fetchImpl) {
      throw new KeywayError("invalid_request", "no fetch implementation available");
    }
    this.fetchImpl = fetchImpl;
    this.timeoutMs = options.timeoutMs;
  }

  /**
   * Build the redirect your app sends the user to. `state` is your own CSRF
   * token; Keyway echoes it back as `?state=` alongside `?code=`.
   */
  buildAuthorizeUrl(params: AuthorizeUrlParams): string {
    const { tenant, redirectUri, state = "", connection = "" } =
      params ?? ({} as AuthorizeUrlParams);
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
   */
  async exchangeCode(params: ExchangeCodeParams): Promise<Identity> {
    const { code, redirectUri, signal } = params ?? ({} as ExchangeCodeParams);
    if (!code || !redirectUri) {
      throw new KeywayError("invalid_request", "code and redirectUri are required");
    }
    const body = new URLSearchParams({ code, redirect_uri: redirectUri });
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        signal: signal ?? (this.timeoutMs ? AbortSignal.timeout(this.timeoutMs) : undefined),
      });
    } catch (err) {
      if (err instanceof KeywayError) throw err;
      throw new KeywayError("network_error", err instanceof Error ? err.message : "request failed");
    }
    if (!res.ok) {
      let codeOut = "invalid_grant";
      let desc: string = res.statusText ?? "";
      try {
        const data: unknown = await res.json();
        if (isRecord(data)) {
          if (typeof data.error === "string" && data.error) codeOut = data.error;
          const detail = data.error_description ?? data.error;
          if (typeof detail === "string" && detail) desc = detail;
        }
      } catch {
        // Non-JSON error body: keep status text.
      }
      throw new KeywayError(codeOut, desc || `request failed with status ${res.status}`, res.status);
    }
    let identity: unknown;
    try {
      identity = await res.json();
    } catch {
      throw new KeywayError("invalid_grant", "could not decode identity");
    }
    if (!isRecord(identity) || typeof identity.email !== "string" || identity.email === "") {
      throw new KeywayError("invalid_grant", "identity has no email");
    }
    return {
      email: identity.email,
      name: typeof identity.name === "string" ? identity.name : "",
      groups: (Array.isArray(identity.groups) ? identity.groups : []) as string[],
    };
  }
}
