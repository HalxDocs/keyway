import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateState, parseCallbackUrl } from "../src/index.js";

describe("generateState", () => {
  it("mints 32-char hex and is unique", () => {
    const a = generateState();
    const b = generateState();
    assert.match(a, /^[0-9a-f]{32}$/);
    assert.notEqual(a, b);
  });
});

describe("parseCallbackUrl", () => {
  it("extracts code and state", () => {
    const { code, state } = parseCallbackUrl("https://app.example/callback?code=abc&state=xyz");
    assert.equal(code, "abc");
    assert.equal(state, "xyz");
  });

  it("returns empty strings for missing params", () => {
    const { code, state } = parseCallbackUrl("https://app.example/callback");
    assert.equal(code, "");
    assert.equal(state, "");
  });
});
