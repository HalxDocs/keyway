import { describe, it, expect, expectTypeOf } from "vitest";
import { generateState, parseCallbackUrl } from "../src/index.js";
import type { Identity, KeywayErrorCode } from "../src/index.js";
import { KeywayClient } from "../src/index.js";

describe("generateState", () => {
  it("mints 32-char hex and is unique", () => {
    const a = generateState();
    const b = generateState();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});

describe("parseCallbackUrl", () => {
  it("extracts code and state", () => {
    const { code, state } = parseCallbackUrl("https://app.example/callback?code=abc&state=xyz");
    expect(code).toBe("abc");
    expect(state).toBe("xyz");
  });

  it("returns empty strings for missing params", () => {
    const { code, state } = parseCallbackUrl("https://app.example/callback");
    expect(code).toBe("");
    expect(state).toBe("");
  });
});

describe("types", () => {
  it("Identity has exactly email/name/groups", () => {
    expectTypeOf<Identity>().toEqualTypeOf<{ email: string; name: string; groups: string[] }>();
  });

  it("known error codes are accepted, arbitrary strings still compile", () => {
    const known: KeywayErrorCode = "invalid_grant";
    const future: KeywayErrorCode = "some_future_code";
    expect(known).toBe("invalid_grant");
    expect(future).toBe("some_future_code");
  });

  it("exchangeCode resolves to Identity", () => {
    const c = new KeywayClient("https://keyway.example");
    expectTypeOf(
      c.exchangeCode({ code: "x", redirectUri: "https://app.example/callback" }),
    ).toEqualTypeOf<Promise<Identity>>();
  });
});
