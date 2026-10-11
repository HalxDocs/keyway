/**
 * Stable machine-readable error codes passed through from the server
 * (`invalid_request`, `invalid_grant`, `login_failed`, ...) plus the two
 * client-side codes (`network_error`, `internal`). The `(string & {})`
 * keeps the union open so new server codes still type-check while known
 * codes get autocomplete.
 */
export type KeywayErrorCode =
  | "invalid_request"
  | "invalid_grant"
  | "login_failed"
  | "unauthorized"
  | "network_error"
  | "internal"
  | (string & {});

/**
 * KeywayError is the single error type thrown by keyway-ts.
 *
 * `code` passes through the server's stable `error` field so callers can
 * switch on it. `description` carries the human-readable
 * `error_description`.
 */
export class KeywayError extends Error {
  readonly code: KeywayErrorCode;
  readonly description: string;
  readonly status?: number;

  constructor(code: KeywayErrorCode, description: string, status?: number) {
    super(description ? `${code}: ${description}` : code);
    this.name = "KeywayError";
    this.code = code;
    this.description = description ?? "";
    if (status !== undefined) this.status = status;
  }
}
