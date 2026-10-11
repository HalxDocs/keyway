/**
 * KeywayError is the single error type thrown by keyway-js.
 *
 * `code` passes through the server's stable `error` field so callers can
 * switch on it (`invalid_request`, `invalid_grant`, `login_failed`, ...).
 * `description` carries the human-readable `error_description`.
 */
export class KeywayError extends Error {
  /**
   * @param {string} code stable machine-readable code
   * @param {string} description human-readable detail
   * @param {number} [status] HTTP status when the error came from a response
   */
  constructor(code, description, status) {
    super(description ? `${code}: ${description}` : code);
    this.name = "KeywayError";
    this.code = code;
    this.description = description ?? "";
    if (status !== undefined) this.status = status;
  }
}
